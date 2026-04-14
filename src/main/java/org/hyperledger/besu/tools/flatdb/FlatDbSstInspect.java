/*
 * Standalone tool to inspect which RocksDB keys share the same SST data block
 * as a given Besu key in the Bonsai state database.
 *
 * Supports two modes:
 *   flat  - ACCOUNT_STORAGE_STORAGE CF (id 0x08), key = keccak256(addr) || keccak256(slot)
 *   trie  - TRIE_BRANCH_STORAGE CF (id 0x09), key = location (account trie) or
 *           keccak256(addr) || location (storage trie)
 */
package org.hyperledger.besu.tools.flatdb;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.ColumnFamilyOptions;
import org.rocksdb.DBOptions;
import org.rocksdb.LiveFileMetaData;
import org.rocksdb.Options;
import org.rocksdb.ReadOptions;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.SstFileReader;
import org.rocksdb.SstFileReaderIterator;
import org.rocksdb.TableProperties;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "besu-sst-inspect",
    mixinStandardHelpOptions = true,
    description =
        "Show all keys in the same RocksDB SST data block as a given Besu state key.")
public class FlatDbSstInspect implements Callable<Integer> {

  private static final byte[] ACCOUNT_STORAGE_CF_ID = new byte[] {8};
  private static final byte[] TRIE_BRANCH_CF_ID = new byte[] {9};
  private static final int FLAT_KEY_LEN = 64;
  private static final int ACCOUNT_HASH_LEN = 32;
  private static final HexFormat HEX = HexFormat.of();

  // ---- Mode selection ----

  @Option(
      names = {"--mode"},
      description = "Inspection mode: 'flat' for flat storage (default), 'trie' for trie branches",
      defaultValue = "flat")
  private String mode;

  // ---- Common options ----

  @Option(
      names = {"--db-path"},
      required = true,
      description = "Path to the Besu RocksDB database directory")
  private File dbPath;

  @Option(
      names = {"--address"},
      description = "Contract address (hex, e.g. 0xdAC17F958D2ee523a2206206994597C13D831ec7)")
  private String address;

  // ---- Flat mode options ----

  @Option(
      names = {"--slot"},
      description = "Storage slot index (hex or decimal, e.g. 0x2 or 2). Used in flat mode.")
  private String slot;

  @Option(
      names = {"--raw-key"},
      description = "Use a pre-computed hex key directly (bypasses address/slot/location encoding)")
  private String rawKey;

  // ---- Trie mode options ----

  @Option(
      names = {"--location"},
      description =
          "Trie node location as hex nibble path (e.g. 0x01 or 0x0a0b). Used in trie mode.")
  private String location;

  @Option(
      names = {"--trie-type"},
      description = "Trie type: 'account' for world state trie, 'storage' for contract storage trie (requires --address)",
      defaultValue = "storage")
  private String trieType;

  // ---- sst_dump options ----

  @Option(
      names = {"--use-sst-dump"},
      description = "Use external sst_dump binary for exact block boundaries")
  private boolean useSstDump = false;

  @Option(
      names = {"--sst-dump-path"},
      description = "Path to the sst_dump binary (default: sst_dump on PATH)")
  private String sstDumpPath = "sst_dump";

  public static void main(String[] args) {
    int exitCode = new CommandLine(new FlatDbSstInspect()).execute(args);
    System.exit(exitCode);
  }

  @Override
  public Integer call() throws Exception {
    RocksDB.loadLibrary();

    return switch (mode.toLowerCase()) {
      case "flat" -> runFlatMode();
      case "trie" -> runTrieMode();
      default -> {
        System.err.println("ERROR: Unknown mode '" + mode + "'. Use 'flat' or 'trie'.");
        yield 1;
      }
    };
  }

  // ========================================================================
  // FLAT MODE: ACCOUNT_STORAGE_STORAGE (CF 0x08)
  // key = keccak256(address) || keccak256(slot)
  // ========================================================================

  private int runFlatMode() throws Exception {
    byte[] targetKey = buildFlatKey();

    System.out.println("=== Besu SST Block Inspector — FLAT STORAGE mode ===");
    System.out.println("Column family: ACCOUNT_STORAGE_STORAGE (0x08)");
    System.out.println("Target key (" + targetKey.length * 2 + " hex): " + HEX.formatHex(targetKey));
    if (targetKey.length == FLAT_KEY_LEN) {
      System.out.println("  account hash : " + HEX.formatHex(targetKey, 0, ACCOUNT_HASH_LEN));
      System.out.println("  slot hash    : " + HEX.formatHex(targetKey, ACCOUNT_HASH_LEN, FLAT_KEY_LEN));
    }
    System.out.println();

    return inspectCf(ACCOUNT_STORAGE_CF_ID, "ACCOUNT_STORAGE_STORAGE", targetKey,
        this::formatFlatBlockResult);
  }

  private byte[] buildFlatKey() {
    if (rawKey != null && !rawKey.isBlank()) {
      return parseRawHexKey(rawKey);
    }
    if (address == null || slot == null) {
      throw new IllegalArgumentException("Flat mode requires --address and --slot (or --raw-key)");
    }

    byte[] addressBytes = parseAddress(address);
    byte[] slotBytes = parseSlotAsUint256(slot);
    byte[] accountHash = keccak256(addressBytes);
    byte[] slotHash = keccak256(slotBytes);

    byte[] key = new byte[FLAT_KEY_LEN];
    System.arraycopy(accountHash, 0, key, 0, ACCOUNT_HASH_LEN);
    System.arraycopy(slotHash, 0, key, ACCOUNT_HASH_LEN, ACCOUNT_HASH_LEN);
    return key;
  }

  // ========================================================================
  // TRIE MODE: TRIE_BRANCH_STORAGE (CF 0x09)
  //   account trie: key = location (nibble path bytes, variable length)
  //   storage trie: key = keccak256(address) || location
  // ========================================================================

  private int runTrieMode() throws Exception {
    byte[] targetKey = buildTrieKey();

    System.out.println("=== Besu SST Block Inspector — TRIE BRANCH mode ===");
    System.out.println("Column family: TRIE_BRANCH_STORAGE (0x09)");
    System.out.println("Trie type: " + trieType);
    System.out.println("Target key (" + targetKey.length * 2 + " hex): " + HEX.formatHex(targetKey));
    if (trieType.equalsIgnoreCase("storage") && targetKey.length > ACCOUNT_HASH_LEN) {
      System.out.println("  account hash : " + HEX.formatHex(targetKey, 0, ACCOUNT_HASH_LEN));
      System.out.println("  location     : " + HEX.formatHex(targetKey, ACCOUNT_HASH_LEN, targetKey.length));
    } else {
      System.out.println("  location     : " + HEX.formatHex(targetKey));
    }
    System.out.println();

    return inspectCf(TRIE_BRANCH_CF_ID, "TRIE_BRANCH_STORAGE", targetKey,
        trieType.equalsIgnoreCase("storage")
            ? this::formatStorageTrieBlockResult
            : this::formatAccountTrieBlockResult);
  }

  private byte[] buildTrieKey() {
    if (rawKey != null && !rawKey.isBlank()) {
      return parseRawHexKey(rawKey);
    }

    byte[] locationBytes = parseLocationBytes(location);

    if (trieType.equalsIgnoreCase("account")) {
      return locationBytes;
    }

    // storage trie: keccak256(address) || location
    if (address == null) {
      throw new IllegalArgumentException(
          "Storage trie mode requires --address (or use --trie-type account)");
    }
    byte[] accountHash = keccak256(parseAddress(address));
    byte[] key = new byte[ACCOUNT_HASH_LEN + locationBytes.length];
    System.arraycopy(accountHash, 0, key, 0, ACCOUNT_HASH_LEN);
    System.arraycopy(locationBytes, 0, key, ACCOUNT_HASH_LEN, locationBytes.length);
    return key;
  }

  private static byte[] parseLocationBytes(String loc) {
    if (loc == null || loc.isBlank()) {
      return new byte[0]; // root node
    }
    String cleaned = loc.startsWith("0x") ? loc.substring(2) : loc;
    if (cleaned.isEmpty()) {
      return new byte[0];
    }
    return HEX.parseHex(cleaned);
  }

  // ========================================================================
  // Common DB + SST inspection logic
  // ========================================================================

  @FunctionalInterface
  private interface BlockFormatter {
    int format(List<byte[]> blockKeys, byte[] targetKey, long blockNum, long totalBlocks,
        boolean exact);
  }

  private int inspectCf(byte[] cfId, String cfName, byte[] targetKey, BlockFormatter formatter)
      throws Exception {
    List<ColumnFamilyDescriptor> cfDescriptors = new ArrayList<>();
    List<ColumnFamilyHandle> cfHandles = new ArrayList<>();

    List<byte[]> existingCFs =
        RocksDB.listColumnFamilies(new org.rocksdb.Options(), dbPath.getAbsolutePath());
    for (byte[] cf : existingCFs) {
      cfDescriptors.add(new ColumnFamilyDescriptor(cf, new ColumnFamilyOptions()));
    }

    ColumnFamilyHandle targetCfHandle = null;

    try (DBOptions dbOptions = new DBOptions();
        RocksDB db =
            RocksDB.openReadOnly(dbOptions, dbPath.getAbsolutePath(), cfDescriptors, cfHandles)) {

      for (int i = 0; i < cfDescriptors.size(); i++) {
        if (Arrays.equals(cfDescriptors.get(i).getName(), cfId)) {
          targetCfHandle = cfHandles.get(i);
          break;
        }
      }

      if (targetCfHandle == null) {
        System.err.println("ERROR: Column family " + cfName + " not found in database.");
        System.err.println("Available CFs:");
        for (byte[] cf : existingCFs) {
          System.err.println("  " + HEX.formatHex(cf));
        }
        return 1;
      }

      System.out.println("Column family " + cfName + " found.");

      try (ReadOptions readOptions = new ReadOptions()) {
        byte[] value = db.get(targetCfHandle, readOptions, targetKey);
        if (value != null) {
          System.out.println(
              "Key EXISTS. Value (" + value.length + " bytes): "
                  + HEX.formatHex(value, 0, Math.min(value.length, 64))
                  + (value.length > 64 ? "..." : ""));
        } else {
          System.out.println(
              "Key NOT found in DB (may be in a different SST level or not stored).");
        }
      }
      System.out.println();

      SstFileInfo sstInfo = findSstForKey(db, cfId, targetKey);
      if (sstInfo == null) {
        System.err.println("ERROR: No SST file found whose key range contains the target key.");
        return 1;
      }

      System.out.println("SST file: " + sstInfo.path);
      System.out.println(
          "  level=" + sstInfo.level + "  entries=" + sstInfo.numEntries
              + "  size=" + formatSize(sstInfo.size));
      System.out.println();

      if (useSstDump) {
        return dumpAndParseBlocksViaSstDump(sstInfo.path, targetKey, formatter);
      } else {
        return inspectBlockViaSstFileReader(sstInfo.path, targetKey, formatter);
      }

    } finally {
      for (ColumnFamilyHandle h : cfHandles) {
        h.close();
      }
    }
  }

  // ---- SST file location ----

  private record SstFileInfo(String path, int level, long numEntries, long size) {}

  private SstFileInfo findSstForKey(RocksDB db, byte[] cfId, byte[] targetKey)
      throws RocksDBException {
    List<LiveFileMetaData> allFiles = db.getLiveFilesMetaData();

    List<LiveFileMetaData> cfFiles = new ArrayList<>();
    for (LiveFileMetaData meta : allFiles) {
      if (Arrays.equals(meta.columnFamilyName(), cfId)) {
        cfFiles.add(meta);
      }
    }

    System.out.println("Found " + cfFiles.size() + " SST files for this CF.");

    List<LiveFileMetaData> candidates = new ArrayList<>();
    for (LiveFileMetaData meta : cfFiles) {
      byte[] smallest = stripInternalKeySuffix(meta.smallestKey());
      byte[] largest = stripInternalKeySuffix(meta.largestKey());
      if (compareBytes(targetKey, smallest) >= 0
          && compareBytes(targetKey, largest) <= 0) {
        candidates.add(meta);
      }
    }

    if (candidates.isEmpty()) {
      return null;
    }

    candidates.sort(Comparator.comparingInt(LiveFileMetaData::level));
    LiveFileMetaData chosen = candidates.get(0);
    return new SstFileInfo(
        chosen.path() + chosen.fileName(), chosen.level(),
        chosen.numEntries(), chosen.size());
  }

  // ---- SstFileReader approach ----

  private int inspectBlockViaSstFileReader(
      String sstFilePath, byte[] targetKey, BlockFormatter formatter) throws RocksDBException {
    System.out.println("Using SstFileReader to inspect block contents...");
    System.out.println();

    try (Options options = new Options();
        SstFileReader reader = new SstFileReader(options)) {

      reader.open(sstFilePath);
      TableProperties props = reader.getTableProperties();

      long numDataBlocks = props.getNumDataBlocks();
      long numEntries = props.getNumEntries();
      long dataSize = props.getDataSize();
      long entriesPerBlock =
          numDataBlocks > 0 ? Math.max(1, numEntries / numDataBlocks) : numEntries;

      System.out.println("SST properties:");
      System.out.println("  data blocks  : " + numDataBlocks);
      System.out.println("  total entries: " + numEntries);
      System.out.println("  data size    : " + formatSize(dataSize));
      System.out.println("  entries/block: ~" + entriesPerBlock);
      System.out.println();

      try (ReadOptions readOptions = new ReadOptions();
          SstFileReaderIterator iter = reader.newIterator(readOptions)) {

        iter.seekToFirst();
        long position = 0;
        boolean foundInFile = false;
        while (iter.isValid()) {
          byte[] userKey = iter.key();
          if (Arrays.equals(userKey, targetKey)) {
            foundInFile = true;
            break;
          }
          if (compareBytes(userKey, targetKey) > 0) {
            break;
          }
          position++;
          iter.next();
        }

        long blockIndex = position / entriesPerBlock;
        long blockStart = blockIndex * entriesPerBlock;
        long blockEnd = Math.min(blockStart + entriesPerBlock, numEntries);

        if (foundInFile) {
          System.out.println("Target at position " + position
              + " → estimated block #" + (blockIndex + 1) + " of " + numDataBlocks);
        } else {
          System.out.println("Target not physically in this SST. Estimated insertion point: position " + position);
        }
        System.out.println();

        iter.seekToFirst();
        long idx = 0;
        while (iter.isValid() && idx < blockStart) {
          idx++;
          iter.next();
        }
        List<byte[]> blockKeys = new ArrayList<>();
        while (iter.isValid() && idx < blockEnd) {
          blockKeys.add(iter.key());
          idx++;
          iter.next();
        }

        return formatter.format(blockKeys, targetKey, blockIndex + 1, numDataBlocks, foundInFile);
      }
    }
  }

  // ---- sst_dump approach ----

  private int dumpAndParseBlocksViaSstDump(
      String sstFilePath, byte[] targetKey, BlockFormatter formatter)
      throws IOException, InterruptedException {
    Path tempFile = Files.createTempFile("sst_raw_dump_", ".txt");
    try {
      System.out.println("Running sst_dump --command=raw on " + sstFilePath + " ...");
      System.out.println();

      ProcessBuilder pb =
          new ProcessBuilder(sstDumpPath, "--file=" + sstFilePath, "--command=raw");
      pb.redirectOutput(tempFile.toFile());
      pb.redirectErrorStream(true);
      Process proc = pb.start();
      int exitCode = proc.waitFor();

      if (exitCode != 0) {
        System.err.println("sst_dump exited with code " + exitCode);
        Files.lines(tempFile).limit(20).forEach(System.err::println);
        return 1;
      }

      return parseRawDump(tempFile, targetKey, formatter);
    } finally {
      Files.deleteIfExists(tempFile);
    }
  }

  private int parseRawDump(Path dumpFile, byte[] targetKey, BlockFormatter formatter)
      throws IOException {
    String targetHex = HEX.formatHex(targetKey).toUpperCase();

    List<byte[]> currentBlockKeys = new ArrayList<>();
    String currentBlockHeader = null;
    boolean foundTarget = false;
    List<byte[]> matchedBlockKeys = null;
    String matchedBlockHeader = null;
    int totalBlocks = 0;

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
          if (trimmed.startsWith("HEX ")) {
            String rest = trimmed.substring(4);
            int colonIdx = rest.indexOf(':');
            if (colonIdx > 0) {
              String keyHex = rest.substring(0, colonIdx).trim().toUpperCase();
              String userKeyHex = keyHex.length() > 16
                  ? keyHex.substring(0, keyHex.length() - 16) : keyHex;
              try {
                currentBlockKeys.add(HEX.parseHex(userKeyHex.toLowerCase()));
              } catch (Exception e) {
                // skip malformed
              }
              if (userKeyHex.equalsIgnoreCase(targetHex)) {
                foundTarget = true;
              }
            }
          }
        }
      }
      if (foundTarget && matchedBlockKeys == null) {
        matchedBlockKeys = new ArrayList<>(currentBlockKeys);
        matchedBlockHeader = currentBlockHeader;
      }
    }

    if (matchedBlockKeys == null) {
      System.err.println("Target key not found in sst_dump output.");
      return 1;
    }

    System.out.println("Exact block: " + matchedBlockHeader);
    return formatter.format(matchedBlockKeys, targetKey, -1, totalBlocks, true);
  }

  // ========================================================================
  // Output formatters
  // ========================================================================

  private int formatFlatBlockResult(
      List<byte[]> blockKeys, byte[] targetKey, long blockNum, long totalBlocks, boolean exact) {

    System.out.println("=== RESULT: " + (exact ? "" : "Estimated ") + "keys in same data block ===");
    if (blockNum > 0) {
      System.out.println("Block #" + blockNum + " of " + totalBlocks);
    }
    System.out.println("Total keys in block: " + blockKeys.size());
    System.out.println();

    Map<String, List<byte[]>> byAccount = new HashMap<>();
    for (byte[] key : blockKeys) {
      String accHash = key.length >= ACCOUNT_HASH_LEN
          ? HEX.formatHex(key, 0, ACCOUNT_HASH_LEN) : HEX.formatHex(key);
      byAccount.computeIfAbsent(accHash, k -> new ArrayList<>()).add(key);
    }

    String targetAccHash = targetKey.length >= ACCOUNT_HASH_LEN
        ? HEX.formatHex(targetKey, 0, ACCOUNT_HASH_LEN) : "";

    System.out.println(byAccount.size() + " distinct account(s) in this block:");
    System.out.println();

    List<String> accountHashes = new ArrayList<>(byAccount.keySet());
    accountHashes.sort((a, b) -> {
      if (a.equals(targetAccHash)) return -1;
      if (b.equals(targetAccHash)) return 1;
      return a.compareTo(b);
    });

    for (String accHash : accountHashes) {
      List<byte[]> slots = byAccount.get(accHash);
      boolean isTgt = accHash.equals(targetAccHash);
      System.out.println("  Account: " + accHash
          + (isTgt ? " (TARGET - " + slots.size() + " slots)" : " (" + slots.size() + " slots)"));
      for (byte[] key : slots) {
        boolean isTarget = Arrays.equals(key, targetKey);
        String slotHash = key.length == FLAT_KEY_LEN
            ? HEX.formatHex(key, ACCOUNT_HASH_LEN, FLAT_KEY_LEN) : "?";
        System.out.println(
            (isTarget ? "    >>> " : "        ") + "slot_hash: " + slotHash
                + (isTarget ? "  <-- TARGET" : ""));
      }
      System.out.println();
    }

    printSummary(blockKeys.size(), exact);
    return 0;
  }

  private int formatStorageTrieBlockResult(
      List<byte[]> blockKeys, byte[] targetKey, long blockNum, long totalBlocks, boolean exact) {

    System.out.println("=== RESULT: " + (exact ? "" : "Estimated ") + "trie nodes in same data block ===");
    if (blockNum > 0) {
      System.out.println("Block #" + blockNum + " of " + totalBlocks);
    }
    System.out.println("Total keys in block: " + blockKeys.size());
    System.out.println();

    // Storage trie keys: keccak256(address) || location
    // Group by account hash (first 32 bytes)
    Map<String, List<byte[]>> byAccount = new HashMap<>();
    for (byte[] key : blockKeys) {
      String accHash = key.length >= ACCOUNT_HASH_LEN
          ? HEX.formatHex(key, 0, ACCOUNT_HASH_LEN) : "(short)";
      byAccount.computeIfAbsent(accHash, k -> new ArrayList<>()).add(key);
    }

    String targetAccHash = targetKey.length >= ACCOUNT_HASH_LEN
        ? HEX.formatHex(targetKey, 0, ACCOUNT_HASH_LEN) : "";

    System.out.println(byAccount.size() + " distinct account(s)' trie nodes in this block:");
    System.out.println();

    for (var entry : byAccount.entrySet()) {
      String accHash = entry.getKey();
      List<byte[]> nodes = entry.getValue();
      boolean isTgt = accHash.equals(targetAccHash);
      System.out.println("  Account: " + accHash
          + (isTgt ? " (TARGET - " + nodes.size() + " nodes)" : " (" + nodes.size() + " nodes)"));
      for (byte[] key : nodes) {
        boolean isTarget = Arrays.equals(key, targetKey);
        String loc = key.length > ACCOUNT_HASH_LEN
            ? HEX.formatHex(key, ACCOUNT_HASH_LEN, key.length) : "(root)";
        System.out.println(
            (isTarget ? "    >>> " : "        ") + "location: " + loc
                + " (depth " + (key.length - ACCOUNT_HASH_LEN) + ")"
                + (isTarget ? "  <-- TARGET" : ""));
      }
      System.out.println();
    }

    printSummary(blockKeys.size(), exact);
    return 0;
  }

  private int formatAccountTrieBlockResult(
      List<byte[]> blockKeys, byte[] targetKey, long blockNum, long totalBlocks, boolean exact) {

    System.out.println("=== RESULT: " + (exact ? "" : "Estimated ") + "account trie nodes in same data block ===");
    if (blockNum > 0) {
      System.out.println("Block #" + blockNum + " of " + totalBlocks);
    }
    System.out.println("Total keys in block: " + blockKeys.size());
    System.out.println();

    for (byte[] key : blockKeys) {
      boolean isTarget = Arrays.equals(key, targetKey);
      String loc = key.length > 0 ? HEX.formatHex(key) : "(root)";
      System.out.println(
          (isTarget ? ">>> " : "    ") + "location: " + loc
              + " (depth " + key.length + ")"
              + (isTarget ? "  <-- TARGET" : ""));
    }
    System.out.println();

    printSummary(blockKeys.size(), exact);
    return 0;
  }

  private void printSummary(int blockSize, boolean exact) {
    System.out.println("--- Summary ---");
    System.out.println(
        "When Besu reads this key, RocksDB loads the entire ~32KiB data block.");
    System.out.println("All " + blockSize + " keys above become cached by that single Get().");
    if (!exact) {
      System.out.println();
      System.out.println(
          "NOTE: Block boundaries are estimated. Use --use-sst-dump for exact results.");
    }
  }

  // ========================================================================
  // Shared utilities
  // ========================================================================

  private static byte[] parseRawHexKey(String hex) {
    String cleaned = hex.startsWith("0x") ? hex.substring(2) : hex;
    return HEX.parseHex(cleaned);
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
    BigInteger val = slotStr.startsWith("0x")
        ? new BigInteger(cleaned, 16) : new BigInteger(cleaned);
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

  private static byte[] stripInternalKeySuffix(byte[] internalKey) {
    if (internalKey.length > 8) {
      return Arrays.copyOf(internalKey, internalKey.length - 8);
    }
    return internalKey;
  }

  private static int compareBytes(byte[] a, byte[] b) {
    int minLen = Math.min(a.length, b.length);
    for (int i = 0; i < minLen; i++) {
      int cmp = Byte.compareUnsigned(a[i], b[i]);
      if (cmp != 0) return cmp;
    }
    return Integer.compare(a.length, b.length);
  }

  private static String formatSize(long bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return String.format("%.1f KiB", bytes / 1024.0);
    return String.format("%.1f MiB", bytes / (1024.0 * 1024.0));
  }
}
