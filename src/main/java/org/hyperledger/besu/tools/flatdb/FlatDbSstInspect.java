/*
 * Standalone tool to inspect which RocksDB keys share the same SST data block
 * as a given Besu flat-DB storage slot key.
 *
 * Key encoding mirrors Besu's BonsaiFlatDbStrategy:
 *   ACCOUNT_STORAGE_STORAGE CF (id = 0x08)
 *   key = keccak256(address_20_bytes) || keccak256(slot_as_uint256_32_bytes)
 *
 * Usage:
 *   ./gradlew run --args='--db-path /data/besu/database --address 0xdAC17F958D2ee523a2206206994597C13D831ec7 --slot 0x2'
 */
package org.hyperledger.besu.tools.flatdb;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.ColumnFamilyOptions;
import org.rocksdb.DBOptions;
import org.rocksdb.LiveFileMetaData;
import org.rocksdb.ReadOptions;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "flatdb-sst-inspect",
    mixinStandardHelpOptions = true,
    description =
        "Show all keys in the same RocksDB SST data block as a given Besu flat-DB storage slot.")
public class FlatDbSstInspect implements Callable<Integer> {

  private static final byte[] ACCOUNT_STORAGE_CF_ID = new byte[] {8};
  private static final HexFormat HEX = HexFormat.of();

  @Option(
      names = {"--db-path"},
      required = true,
      description = "Path to the Besu RocksDB database directory")
  private File dbPath;

  @Option(
      names = {"--address"},
      required = true,
      description = "Contract address (hex, e.g. 0xdAC17F958D2ee523a2206206994597C13D831ec7)")
  private String address;

  @Option(
      names = {"--slot"},
      required = true,
      description = "Storage slot index (hex or decimal, e.g. 0x2 or 2)")
  private String slot;

  @Option(
      names = {"--sst-dump-path"},
      description = "Path to the sst_dump binary (default: sst_dump on PATH)")
  private String sstDumpPath = "sst_dump";

  @Option(
      names = {"--raw-key"},
      description =
          "Use a pre-computed 64-byte hex key instead of --address/--slot (128 hex chars)")
  private String rawKey;

  public static void main(String[] args) {
    int exitCode = new CommandLine(new FlatDbSstInspect()).execute(args);
    System.exit(exitCode);
  }

  @Override
  public Integer call() throws Exception {
    RocksDB.loadLibrary();

    byte[] targetKey = buildTargetKey();
    System.out.println("=== Besu Flat-DB SST Block Inspector ===");
    System.out.println("Target key (128 hex): " + HEX.formatHex(targetKey));
    System.out.println("  account hash : " + HEX.formatHex(targetKey, 0, 32));
    System.out.println("  slot hash    : " + HEX.formatHex(targetKey, 32, 64));
    System.out.println();

    List<ColumnFamilyDescriptor> cfDescriptors = new ArrayList<>();
    List<ColumnFamilyHandle> cfHandles = new ArrayList<>();

    List<byte[]> existingCFs = RocksDB.listColumnFamilies(new org.rocksdb.Options(), dbPath.getAbsolutePath());
    for (byte[] cf : existingCFs) {
      cfDescriptors.add(new ColumnFamilyDescriptor(cf, new ColumnFamilyOptions()));
    }

    ColumnFamilyHandle storageCfHandle = null;

    try (DBOptions dbOptions = new DBOptions();
        RocksDB db =
            RocksDB.openReadOnly(dbOptions, dbPath.getAbsolutePath(), cfDescriptors, cfHandles)) {

      for (int i = 0; i < cfDescriptors.size(); i++) {
        if (Arrays.equals(cfDescriptors.get(i).getName(), ACCOUNT_STORAGE_CF_ID)) {
          storageCfHandle = cfHandles.get(i);
          break;
        }
      }

      if (storageCfHandle == null) {
        System.err.println(
            "ERROR: Column family ACCOUNT_STORAGE_STORAGE (0x08) not found in database.");
        System.err.println("Available CFs:");
        for (byte[] cf : existingCFs) {
          System.err.println("  " + HEX.formatHex(cf) + " (" + new String(cf, StandardCharsets.UTF_8) + ")");
        }
        return 1;
      }

      System.out.println("Column family ACCOUNT_STORAGE_STORAGE (0x08) found.");

      try (ReadOptions readOptions = new ReadOptions()) {
        byte[] value = db.get(storageCfHandle, readOptions, targetKey);
        if (value != null) {
          System.out.println("Key EXISTS in flat DB. Value (" + value.length + " bytes): " + HEX.formatHex(value));
        } else {
          System.out.println("WARNING: Key NOT found in flat DB. The slot may not be stored or the encoding may differ.");
        }
      }
      System.out.println();

      String sstFile = findSstForKey(db, storageCfHandle, targetKey);
      if (sstFile == null) {
        System.err.println("ERROR: Could not find an SST file whose key range contains the target key.");
        return 1;
      }

      System.out.println("SST file containing key: " + sstFile);
      System.out.println();

      return dumpAndParseBlocks(sstFile, targetKey);

    } finally {
      for (ColumnFamilyHandle h : cfHandles) {
        h.close();
      }
    }
  }

  private byte[] buildTargetKey() {
    if (rawKey != null && !rawKey.isBlank()) {
      String cleaned = rawKey.startsWith("0x") ? rawKey.substring(2) : rawKey;
      byte[] key = HEX.parseHex(cleaned);
      if (key.length != 64) {
        throw new IllegalArgumentException("--raw-key must be exactly 64 bytes (128 hex chars), got " + key.length);
      }
      return key;
    }

    byte[] addressBytes = parseAddress(address);
    byte[] slotBytes = parseSlotAsUint256(slot);

    byte[] accountHash = keccak256(addressBytes);
    byte[] slotHash = keccak256(slotBytes);

    byte[] key = new byte[64];
    System.arraycopy(accountHash, 0, key, 0, 32);
    System.arraycopy(slotHash, 0, key, 32, 32);
    return key;
  }

  private static byte[] parseAddress(String addr) {
    String cleaned = addr.startsWith("0x") ? addr.substring(2) : addr;
    byte[] bytes = HEX.parseHex(cleaned);
    if (bytes.length != 20) {
      throw new IllegalArgumentException("Address must be 20 bytes, got " + bytes.length);
    }
    return bytes;
  }

  private static byte[] parseSlotAsUint256(String slotStr) {
    String cleaned = slotStr.startsWith("0x") ? slotStr.substring(2) : slotStr;
    BigInteger val;
    if (slotStr.startsWith("0x")) {
      val = new BigInteger(cleaned, 16);
    } else {
      val = new BigInteger(cleaned);
    }
    byte[] raw = val.toByteArray();
    byte[] padded = new byte[32];
    if (raw.length <= 32) {
      System.arraycopy(raw, 0, padded, 32 - raw.length, raw.length);
    } else if (raw.length == 33 && raw[0] == 0) {
      System.arraycopy(raw, 1, padded, 0, 32);
    } else {
      throw new IllegalArgumentException("Slot value too large for uint256");
    }
    return padded;
  }

  private static byte[] keccak256(byte[] input) {
    Keccak.Digest256 digest = new Keccak.Digest256();
    return digest.digest(input);
  }

  private String findSstForKey(RocksDB db, ColumnFamilyHandle cfHandle, byte[] targetKey)
      throws RocksDBException {
    List<LiveFileMetaData> allFiles = db.getLiveFilesMetaData();

    List<LiveFileMetaData> cfFiles = new ArrayList<>();
    for (LiveFileMetaData meta : allFiles) {
      if (Arrays.equals(meta.columnFamilyName(), ACCOUNT_STORAGE_CF_ID)) {
        cfFiles.add(meta);
      }
    }

    System.out.println("Found " + cfFiles.size() + " SST files for ACCOUNT_STORAGE_STORAGE CF.");

    List<LiveFileMetaData> candidates = new ArrayList<>();
    for (LiveFileMetaData meta : cfFiles) {
      if (compareBytes(targetKey, meta.smallestKey()) >= 0
          && compareBytes(targetKey, meta.largestKey()) <= 0) {
        candidates.add(meta);
      }
    }

    if (candidates.isEmpty()) {
      return null;
    }

    candidates.sort(Comparator.comparingInt(LiveFileMetaData::level));
    LiveFileMetaData chosen = candidates.get(0);
    return chosen.path() + chosen.fileName();
  }

  private static int compareBytes(byte[] a, byte[] b) {
    int minLen = Math.min(a.length, b.length);
    for (int i = 0; i < minLen; i++) {
      int cmp = Byte.compareUnsigned(a[i], b[i]);
      if (cmp != 0) return cmp;
    }
    return Integer.compare(a.length, b.length);
  }

  private int dumpAndParseBlocks(String sstFilePath, byte[] targetKey) throws IOException, InterruptedException {
    Path tempFile = Files.createTempFile("sst_raw_dump_", ".txt");
    try {
      System.out.println("Running sst_dump --command=raw on " + sstFilePath + " ...");
      System.out.println("(This may take a while for large SST files)");
      System.out.println();

      ProcessBuilder pb = new ProcessBuilder(sstDumpPath, "--file=" + sstFilePath, "--command=raw");
      pb.redirectOutput(tempFile.toFile());
      pb.redirectErrorStream(true);
      Process proc = pb.start();
      int exitCode = proc.waitFor();

      if (exitCode != 0) {
        System.err.println("sst_dump exited with code " + exitCode);
        System.err.println("Output:");
        Files.lines(tempFile).limit(50).forEach(System.err::println);
        System.err.println();
        System.err.println("Make sure sst_dump (RocksDB 9.7.x) is installed and on your PATH,");
        System.err.println("or pass --sst-dump-path=/path/to/sst_dump");
        return 1;
      }

      return parseRawDump(tempFile, targetKey);
    } finally {
      Files.deleteIfExists(tempFile);
    }
  }

  /**
   * Parse the raw dump output. The format from BlockBasedTable::DumpTable is:
   *
   * Data Block # N @ offset size
   * --------------------------------------
   *   HEX <user_key_hex>: <value_hex>
   *   ASCII ...
   *   ------
   *   HEX <user_key_hex>: <value_hex>
   *   ...
   *
   * We group keys per data block, find the block that contains our target key,
   * and print all keys in that block.
   */
  private int parseRawDump(Path dumpFile, byte[] targetKey) throws IOException {
    String targetHex = HEX.formatHex(targetKey).toUpperCase();

    List<String> currentBlockKeys = new ArrayList<>();
    String currentBlockHeader = null;
    boolean foundTarget = false;
    String matchedBlockHeader = null;
    List<String> matchedBlockKeys = null;

    int totalBlocks = 0;
    int totalKeys = 0;

    try (BufferedReader reader = Files.newBufferedReader(dumpFile)) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("Data Block #")) {
          if (foundTarget && matchedBlockKeys == null) {
            matchedBlockKeys = new ArrayList<>(currentBlockKeys);
            matchedBlockHeader = currentBlockHeader;
          }
          totalBlocks++;
          currentBlockKeys.clear();
          currentBlockHeader = line.trim();
          foundTarget = false;
          continue;
        }

        if (line.startsWith("  HEX ") || line.startsWith(" HEX ")) {
          String trimmed = line.trim();
          // format: "HEX <key_hex>: <value_hex>"
          if (trimmed.startsWith("HEX ")) {
            String rest = trimmed.substring(4);
            int colonIdx = rest.indexOf(':');
            if (colonIdx > 0) {
              String keyHex = rest.substring(0, colonIdx).trim().toUpperCase();
              // RocksDB internal key = user_key + 8 bytes (seq + type).
              // The user key is everything except the last 8 bytes (16 hex chars).
              String userKeyHex = keyHex;
              if (keyHex.length() > 16) {
                userKeyHex = keyHex.substring(0, keyHex.length() - 16);
              }
              currentBlockKeys.add(userKeyHex);
              totalKeys++;
              if (userKeyHex.equalsIgnoreCase(targetHex)) {
                foundTarget = true;
              }
            }
          }
        }
      }

      // Handle last block
      if (foundTarget && matchedBlockKeys == null) {
        matchedBlockKeys = new ArrayList<>(currentBlockKeys);
        matchedBlockHeader = currentBlockHeader;
      }
    }

    System.out.println("SST file stats: " + totalBlocks + " data blocks, " + totalKeys + " total keys");
    System.out.println();

    if (matchedBlockKeys == null) {
      System.err.println("WARNING: Target key was not found in any data block of this SST file.");
      System.err.println("The key might be in a different SST file, or the raw dump format may differ.");
      return 1;
    }

    System.out.println("=== RESULT: Keys in the same data block as target ===");
    System.out.println("Block: " + matchedBlockHeader);
    System.out.println("Total keys in block: " + matchedBlockKeys.size());
    System.out.println();

    for (String keyHex : matchedBlockKeys) {
      boolean isTarget = keyHex.equalsIgnoreCase(targetHex);
      String marker = isTarget ? " <-- TARGET" : "";

      if (keyHex.length() == 128) {
        String accHash = keyHex.substring(0, 64);
        String slotHash = keyHex.substring(64, 128);
        System.out.println(
            (isTarget ? ">>> " : "    ") + keyHex + marker);
        System.out.println("        account_hash=" + accHash.toLowerCase() + " slot_hash=" + slotHash.toLowerCase());
      } else {
        System.out.println(
            (isTarget ? ">>> " : "    ") + keyHex + marker);
      }
    }

    System.out.println();
    System.out.println("When Besu reads this storage slot from the flat DB, RocksDB loads the");
    System.out.println("entire ~32KiB data block above into the block cache. All " + matchedBlockKeys.size() + " keys");
    System.out.println("become cached as a side effect of that single Get().");

    return 0;
  }
}
