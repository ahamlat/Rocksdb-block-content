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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.rocksdb.BlockBasedTableConfig;
import org.rocksdb.ColumnFamilyDescriptor;
import org.rocksdb.ColumnFamilyHandle;
import org.rocksdb.ColumnFamilyOptions;
import org.rocksdb.DBOptions;
import org.rocksdb.LRUCache;
import org.rocksdb.LiveFileMetaData;
import org.rocksdb.Options;
import org.rocksdb.ReadOptions;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.SstFileReader;
import org.rocksdb.SstFileReaderIterator;
import org.rocksdb.Statistics;
import org.rocksdb.TableProperties;
import org.rocksdb.TickerType;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "besu-sst-inspect",
    mixinStandardHelpOptions = true,
    description =
        "Show all keys in the same RocksDB SST data block as a given Besu state key.")
public class FlatDbSstInspect implements Callable<Integer> {

  private static final byte[] ACCOUNT_INFO_CF_ID = new byte[] {6};
  private static final byte[] ACCOUNT_STORAGE_CF_ID = new byte[] {8};
  private static final byte[] TRIE_BRANCH_CF_ID = new byte[] {9};
  private static final int FLAT_KEY_LEN = 64;
  private static final int ACCOUNT_HASH_LEN = 32;
  private static final HexFormat HEX = HexFormat.of();

  // ---- Mode selection ----

  @Option(
      names = {"--mode"},
      description = "Inspection mode: 'flat' (default), 'account', 'trie', or 'batch' (replay a file of storage reads)",
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

  // ---- Batch mode options ----

  @Option(
      names = {"--input-file"},
      description = "File containing flat keys to replay (one per line, format: 'key : 0x<accHash> 0x<slotHash>')")
  private File inputFile;

  @Option(
      names = {"--block-number"},
      description = "Ethereum block number (for display purposes)")
  private String blockNumber;

  // ---- Verification options ----

  @Option(
      names = {"--verify"},
      description =
          "After identifying block neighbors, read target then all neighbors and verify they are served from block cache")
  private boolean verify = false;

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
      case "account" -> runAccountMode();
      case "trie" -> runTrieMode();
      case "batch" -> runBatchMode();
      default -> {
        System.err.println("ERROR: Unknown mode '" + mode + "'. Use 'flat', 'account', 'trie', or 'batch'.");
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
  // ACCOUNT MODE: ACCOUNT_INFO_STATE (CF 0x06)
  // key = keccak256(address)
  // ========================================================================

  private int runAccountMode() throws Exception {
    byte[] targetKey = buildAccountKey();

    System.out.println("=== Besu SST Block Inspector — FLAT ACCOUNT mode ===");
    System.out.println("Column family: ACCOUNT_INFO_STATE (0x06)");
    System.out.println("Target key (" + targetKey.length * 2 + " hex): " + HEX.formatHex(targetKey));
    System.out.println("  account hash : " + HEX.formatHex(targetKey));
    System.out.println();

    return inspectCf(ACCOUNT_INFO_CF_ID, "ACCOUNT_INFO_STATE", targetKey,
        this::formatAccountFlatBlockResult);
  }

  private byte[] buildAccountKey() {
    if (rawKey != null && !rawKey.isBlank()) {
      return parseRawHexKey(rawKey);
    }
    if (address == null) {
      throw new IllegalArgumentException("Account mode requires --address (or --raw-key)");
    }
    return keccak256(parseAddress(address));
  }

  // ========================================================================
  // BATCH MODE: replay a file of storage reads, compute cache hit ratio
  // ========================================================================

  private static final class ByteArrayKey {
    private final byte[] data;
    private final int hash;

    ByteArrayKey(byte[] data) {
      this.data = data;
      this.hash = Arrays.hashCode(data);
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof ByteArrayKey other && Arrays.equals(data, other.data);
    }

    @Override
    public int hashCode() {
      return hash;
    }
  }

  private enum ReadStatus { CACHE_HIT, CACHE_MISS, MEMTABLE, NOT_FOUND }

  private record ParsedKey(byte[] flatKey, String address, String originalSlot) {}

  private record BatchKeyResult(
      byte[] key, ReadStatus status, int valueLen, int neighborsInInput, int neighborsTotal,
      String address, String originalSlot) {}

  private int runBatchMode() throws Exception {
    if (inputFile == null) {
      System.err.println("ERROR: --input-file is required for batch mode.");
      return 1;
    }

    List<ParsedKey> parsedKeys = parseInputFile(inputFile.toPath());
    if (parsedKeys.isEmpty()) {
      System.err.println("ERROR: No keys parsed from input file.");
      return 1;
    }

    Set<ByteArrayKey> keySet = new HashSet<>();
    for (ParsedKey pk : parsedKeys) {
      keySet.add(new ByteArrayKey(pk.flatKey));
    }

    // deduplicate while preserving order
    List<ParsedKey> uniqueParsed = new ArrayList<>();
    Set<ByteArrayKey> seen = new LinkedHashSet<>();
    for (ParsedKey pk : parsedKeys) {
      if (seen.add(new ByteArrayKey(pk.flatKey))) {
        uniqueParsed.add(pk);
      }
    }

    System.out.println("=== Besu SST Block Inspector — BATCH mode ===");
    if (blockNumber != null) {
      System.out.println("Ethereum block: " + blockNumber);
    }
    System.out.println("Input file: " + inputFile.getAbsolutePath());
    System.out.println("Total lines: " + parsedKeys.size());
    System.out.println("Unique keys: " + uniqueParsed.size());
    System.out.println("Column family: ACCOUNT_STORAGE_STORAGE (0x08)");
    System.out.println();

    List<byte[]> existingCFs =
        RocksDB.listColumnFamilies(new Options(), dbPath.getAbsolutePath());

    Statistics stats = new Statistics();
    LRUCache lruCache = new LRUCache(64 * 1024 * 1024);

    List<ColumnFamilyDescriptor> cfDescriptors = new ArrayList<>();
    List<ColumnFamilyHandle> cfHandles = new ArrayList<>();

    for (byte[] cf : existingCFs) {
      ColumnFamilyOptions cfOpts = new ColumnFamilyOptions();
      BlockBasedTableConfig tableConfig = new BlockBasedTableConfig();
      tableConfig.setBlockCache(lruCache);
      cfOpts.setTableFormatConfig(tableConfig);
      cfDescriptors.add(new ColumnFamilyDescriptor(cf, cfOpts));
    }

    try (DBOptions dbOptions = new DBOptions()) {
      dbOptions.setStatistics(stats);

      try (RocksDB db =
          RocksDB.openReadOnly(dbOptions, dbPath.getAbsolutePath(), cfDescriptors, cfHandles)) {

        ColumnFamilyHandle cfHandle = null;
        for (int i = 0; i < cfDescriptors.size(); i++) {
          if (Arrays.equals(cfDescriptors.get(i).getName(), ACCOUNT_STORAGE_CF_ID)) {
            cfHandle = cfHandles.get(i);
            break;
          }
        }
        if (cfHandle == null) {
          System.err.println("ERROR: ACCOUNT_STORAGE_STORAGE CF not found.");
          return 1;
        }

        System.out.println("Column family found. Reading " + uniqueParsed.size() + " keys sequentially...");
        System.out.println();

        List<BatchKeyResult> results = new ArrayList<>();
        List<byte[]> missKeys = new ArrayList<>();

        int hitCount = 0, missCount = 0, memCount = 0, notFoundCount = 0;

        try (ReadOptions ro = new ReadOptions()) {
          for (int i = 0; i < uniqueParsed.size(); i++) {
            ParsedKey pk = uniqueParsed.get(i);
            byte[] key = pk.flatKey;
            resetAllCacheCounters(stats);

            byte[] value = db.get(cfHandle, ro, key);

            long dataMiss = stats.getTickerCount(TickerType.BLOCK_CACHE_DATA_MISS);
            long totalMiss = stats.getTickerCount(TickerType.BLOCK_CACHE_MISS);
            long totalHit = stats.getTickerCount(TickerType.BLOCK_CACHE_HIT);

            ReadStatus status;
            if (value == null) {
              status = ReadStatus.NOT_FOUND;
              notFoundCount++;
            } else if (totalMiss == 0 && totalHit == 0) {
              status = ReadStatus.MEMTABLE;
              memCount++;
            } else if (dataMiss > 0) {
              status = ReadStatus.CACHE_MISS;
              missCount++;
              missKeys.add(key);
            } else {
              status = ReadStatus.CACHE_HIT;
              hitCount++;
            }

            results.add(new BatchKeyResult(
                key, status, value != null ? value.length : 0, -1, -1,
                pk.address, pk.originalSlot));

            String display;
            if (pk.address != null) {
              String slotStr = pk.originalSlot != null ? pk.originalSlot : "?";
              display = String.format("addr:%s slot:%s", pk.address, slotStr);
            } else {
              String accHash = HEX.formatHex(key, 0, Math.min(ACCOUNT_HASH_LEN, key.length));
              String slotHash = key.length == FLAT_KEY_LEN
                  ? HEX.formatHex(key, ACCOUNT_HASH_LEN, FLAT_KEY_LEN) : "?";
              display = String.format("accHash:%s slot:%s", accHash, slotHash);
            }

            System.out.printf("[%4d] %-10s %s", i + 1, status, display);
            if (value != null) {
              System.out.printf(" value:%dB", value.length);
            }
            System.out.println();
          }
        }

        System.out.println();

        // Neighbor analysis for MISS keys
        System.out.println("Analyzing block neighbors for " + missKeys.size() + " CACHE_MISS keys...");
        System.out.println();

        long totalNeighborsInInput = 0;
        long totalNeighborsCount = 0;
        int analyzedMisses = 0;

        for (byte[] missKey : missKeys) {
          SstFileInfo sstInfo = findSstForKeyQuiet(db, ACCOUNT_STORAGE_CF_ID, missKey);
          if (sstInfo == null) continue;

          List<byte[]> blockKeys = getBlockKeysForKey(sstInfo.path, missKey);
          if (blockKeys == null || blockKeys.isEmpty()) continue;

          int neighborsInInput = 0;
          for (byte[] bk : blockKeys) {
            if (keySet.contains(new ByteArrayKey(bk))) {
              neighborsInInput++;
            }
          }

          totalNeighborsInInput += neighborsInInput;
          totalNeighborsCount += blockKeys.size();
          analyzedMisses++;

          String accHash = HEX.formatHex(missKey, 0, Math.min(ACCOUNT_HASH_LEN, missKey.length));
          String slotHash = missKey.length == FLAT_KEY_LEN
              ? HEX.formatHex(missKey, ACCOUNT_HASH_LEN, FLAT_KEY_LEN) : "?";
          System.out.printf("  MISS accHash:%s slot:%s  neighbors_in_input: %d / %d%n",
              accHash, slotHash, neighborsInInput, blockKeys.size());
        }

        // Print summary
        System.out.println();
        System.out.println("=== BATCH CACHE ANALYSIS SUMMARY ===");
        if (blockNumber != null) {
          System.out.println("Ethereum block: " + blockNumber);
        }
        System.out.println();

        int total = uniqueParsed.size();
        int found = total - notFoundCount;

        System.out.println("Input keys      : " + total);
        System.out.printf("Reads found     : %d (%.1f%%)%n", found,
            total > 0 ? found * 100.0 / total : 0);
        System.out.println("Not found in DB : " + notFoundCount);
        System.out.println();

        System.out.println("Cache status (of " + found + " found keys):");
        System.out.printf("  CACHE_HIT  : %5d (%.1f%%)%n", hitCount,
            found > 0 ? hitCount * 100.0 / found : 0);
        System.out.printf("  CACHE_MISS : %5d (%.1f%%)%n", missCount,
            found > 0 ? missCount * 100.0 / found : 0);
        System.out.printf("  MEMTABLE   : %5d (%.1f%%)%n", memCount,
            found > 0 ? memCount * 100.0 / found : 0);
        System.out.println();

        if (analyzedMisses > 0) {
          double avgNeighborsInInput = (double) totalNeighborsInInput / analyzedMisses;
          double avgBlockSize = (double) totalNeighborsCount / analyzedMisses;
          System.out.println("Block neighbor analysis (" + analyzedMisses + " CACHE_MISS keys analyzed):");
          System.out.printf("  Avg neighbors from same block also in input: %.1f / %.0f%n",
              avgNeighborsInInput, avgBlockSize);
          System.out.printf("  Each cold read pre-caches ~%.0f future reads for free.%n",
              avgNeighborsInInput);
        }

        // Per-account breakdown
        System.out.println();
        System.out.println("=== PER-ACCOUNT BREAKDOWN ===");
        System.out.println();

        record AccountStats(String address, int hit, int miss, int memtable, int notFound, int total) {}

        Map<String, int[]> accountCounters = new HashMap<>();
        Map<String, String> accountToAddress = new HashMap<>();

        for (BatchKeyResult r : results) {
          String accHash = HEX.formatHex(r.key, 0, Math.min(ACCOUNT_HASH_LEN, r.key.length));
          int[] counts = accountCounters.computeIfAbsent(accHash, k -> new int[4]);
          switch (r.status) {
            case CACHE_HIT -> counts[0]++;
            case CACHE_MISS -> counts[1]++;
            case MEMTABLE -> counts[2]++;
            case NOT_FOUND -> counts[3]++;
          }
          if (r.address != null) {
            accountToAddress.putIfAbsent(accHash, r.address);
          }
        }

        List<Map.Entry<String, int[]>> sortedAccounts = new ArrayList<>(accountCounters.entrySet());
        sortedAccounts.sort((a, b) -> {
          int totalA = a.getValue()[0] + a.getValue()[1] + a.getValue()[2] + a.getValue()[3];
          int totalB = b.getValue()[0] + b.getValue()[1] + b.getValue()[2] + b.getValue()[3];
          return Integer.compare(totalB, totalA);
        });

        System.out.printf("%-44s %6s %6s %6s %6s %8s %8s %8s %8s%n",
            "Account", "HIT", "MISS", "MEMTBL", "NOTFND", "TOTAL", "HIT%", "MISS%", "NOTFND%");
        System.out.println("-".repeat(140));

        for (var entry : sortedAccounts) {
          String accHash = entry.getKey();
          int[] c = entry.getValue();
          int acctTotal = c[0] + c[1] + c[2] + c[3];
          double acctHitPct = acctTotal > 0 ? c[0] * 100.0 / acctTotal : 0;
          double acctMissPct = acctTotal > 0 ? c[1] * 100.0 / acctTotal : 0;
          double acctNotFoundPct = acctTotal > 0 ? c[3] * 100.0 / acctTotal : 0;

          String addr = accountToAddress.get(accHash);
          String label = addr != null ? addr : accHash;

          System.out.printf("%-44s %6d %6d %6d %6d %8d %7.1f%% %7.1f%% %7.1f%%%n",
              label, c[0], c[1], c[2], c[3], acctTotal, acctHitPct, acctMissPct, acctNotFoundPct);
        }

        System.out.println("-".repeat(140));
        double totalHitPct = total > 0 ? hitCount * 100.0 / total : 0;
        double totalMissPct = total > 0 ? missCount * 100.0 / total : 0;
        double totalNotFoundPct = total > 0 ? notFoundCount * 100.0 / total : 0;
        System.out.printf("%-44s %6d %6d %6d %6d %8d %7.1f%% %7.1f%% %7.1f%%%n",
            "TOTAL", hitCount, missCount, memCount, notFoundCount, total,
            totalHitPct, totalMissPct, totalNotFoundPct);

        return 0;

      } finally {
        for (ColumnFamilyHandle h : cfHandles) {
          h.close();
        }
      }
    } finally {
      stats.close();
      lruCache.close();
    }
  }

  private static final Pattern KEY_PATTERN =
      Pattern.compile("key\\s*:\\s*(0x[0-9a-fA-F]{64})\\s+(0x[0-9a-fA-F]{64})");
  private static final Pattern ACCOUNT_PATTERN =
      Pattern.compile("Account\\s+(0x[0-9a-fA-F]{40})");
  private static final Pattern SLOT_PATTERN =
      Pattern.compile("storageSlotKey\\s+Optional\\[(0x[0-9a-fA-F]+)]");

  private List<ParsedKey> parseInputFile(Path path) throws IOException {
    List<ParsedKey> keys = new ArrayList<>();
    try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.isEmpty()) continue;

        // Extract "key : 0x<accHash> 0x<slotHash>" from anywhere in the line
        Matcher keyMatcher = KEY_PATTERN.matcher(line);
        while (keyMatcher.find()) {
          String accHex = keyMatcher.group(1).substring(2);
          String slotHex = keyMatcher.group(2).substring(2);
          try {
            byte[] accHash = HEX.parseHex(accHex);
            byte[] slotHash = HEX.parseHex(slotHex);
            if (accHash.length == ACCOUNT_HASH_LEN && slotHash.length == ACCOUNT_HASH_LEN) {
              byte[] key = new byte[FLAT_KEY_LEN];
              System.arraycopy(accHash, 0, key, 0, ACCOUNT_HASH_LEN);
              System.arraycopy(slotHash, 0, key, ACCOUNT_HASH_LEN, ACCOUNT_HASH_LEN);

              // Try to extract Account address and original slot from context before this key
              String before = line.substring(0, keyMatcher.start());
              String address = null;
              String originalSlot = null;

              // Find the LAST Account + storageSlotKey before this key occurrence
              Matcher accMatcher = ACCOUNT_PATTERN.matcher(before);
              String lastAddr = null;
              while (accMatcher.find()) lastAddr = accMatcher.group(1);
              address = lastAddr;

              Matcher slotMatcher = SLOT_PATTERN.matcher(before);
              String lastSlot = null;
              while (slotMatcher.find()) lastSlot = slotMatcher.group(1);
              originalSlot = lastSlot;

              keys.add(new ParsedKey(key, address, originalSlot));
            }
          } catch (Exception e) {
            // skip malformed
          }
        }
      }
    }
    return keys;
  }

  private SstFileInfo findSstForKeyQuiet(RocksDB db, byte[] cfId, byte[] targetKey)
      throws RocksDBException {
    List<LiveFileMetaData> allFiles = db.getLiveFilesMetaData();
    List<LiveFileMetaData> candidates = new ArrayList<>();
    for (LiveFileMetaData meta : allFiles) {
      if (!Arrays.equals(meta.columnFamilyName(), cfId)) continue;
      byte[] smallest = stripInternalKeySuffix(meta.smallestKey());
      byte[] largest = stripInternalKeySuffix(meta.largestKey());
      if (compareBytes(targetKey, smallest) >= 0 && compareBytes(targetKey, largest) <= 0) {
        candidates.add(meta);
      }
    }
    if (candidates.isEmpty()) return null;
    candidates.sort(Comparator.comparingInt(LiveFileMetaData::level));
    LiveFileMetaData chosen = candidates.get(0);
    return new SstFileInfo(
        chosen.path() + chosen.fileName(), chosen.level(),
        chosen.numEntries(), chosen.size());
  }

  private List<byte[]> getBlockKeysForKey(String sstFilePath, byte[] targetKey)
      throws RocksDBException {
    try (Options options = new Options();
        SstFileReader reader = new SstFileReader(options)) {
      reader.open(sstFilePath);
      TableProperties props = reader.getTableProperties();
      long numDataBlocks = props.getNumDataBlocks();
      long numEntries = props.getNumEntries();
      long entriesPerBlock =
          numDataBlocks > 0 ? Math.max(1, numEntries / numDataBlocks) : numEntries;

      try (ReadOptions readOptions = new ReadOptions();
          SstFileReaderIterator iter = reader.newIterator(readOptions)) {
        iter.seekToFirst();
        long position = 0;
        while (iter.isValid()) {
          byte[] userKey = iter.key();
          if (Arrays.equals(userKey, targetKey) || compareBytes(userKey, targetKey) > 0) {
            break;
          }
          position++;
          iter.next();
        }

        long blockIndex = position / entriesPerBlock;
        long blockStart = blockIndex * entriesPerBlock;
        long blockEnd = Math.min(blockStart + entriesPerBlock, numEntries);

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
        return blockKeys;
      }
    }
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
    List<byte[]> existingCFs =
        RocksDB.listColumnFamilies(new org.rocksdb.Options(), dbPath.getAbsolutePath());

    Statistics stats = verify ? new Statistics() : null;
    LRUCache lruCache = verify ? new LRUCache(64 * 1024 * 1024) : null;

    List<ColumnFamilyDescriptor> cfDescriptors = new ArrayList<>();
    List<ColumnFamilyHandle> cfHandles = new ArrayList<>();

    for (byte[] cf : existingCFs) {
      ColumnFamilyOptions cfOpts = new ColumnFamilyOptions();
      if (verify) {
        BlockBasedTableConfig tableConfig = new BlockBasedTableConfig();
        tableConfig.setBlockCache(lruCache);
        cfOpts.setTableFormatConfig(tableConfig);
      }
      cfDescriptors.add(new ColumnFamilyDescriptor(cf, cfOpts));
    }

    ColumnFamilyHandle targetCfHandle = null;

    try (DBOptions dbOptions = new DBOptions()) {
      if (verify && stats != null) {
        dbOptions.setStatistics(stats);
      }

      try (RocksDB db =
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

        if (!verify) {
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
        } else {
          System.out.println("Skipping existence check to keep block cache cold for verification.");
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

        BlockResult br;
        if (useSstDump) {
          br = dumpAndParseBlocksViaSstDump(sstInfo.path, targetKey);
        } else {
          br = inspectBlockViaSstFileReader(sstInfo.path, targetKey);
        }

        if (br == null) {
          return 1;
        }

        int result = formatter.format(br.keys, targetKey, br.blockNum, br.totalBlocks, br.exact);

        if (verify && stats != null) {
          verifyCacheHits(db, targetCfHandle, stats, targetKey, br.keys);
        }

        return result;

      } finally {
        for (ColumnFamilyHandle h : cfHandles) {
          h.close();
        }
      }
    } finally {
      if (stats != null) stats.close();
      if (lruCache != null) lruCache.close();
    }
  }

  // ---- Cache verification ----

  private void verifyCacheHits(
      RocksDB db,
      ColumnFamilyHandle cfHandle,
      Statistics stats,
      byte[] targetKey,
      List<byte[]> blockKeys)
      throws RocksDBException {

    System.out.println();
    System.out.println("=== CACHE VERIFICATION ===");
    System.out.println();

    // Memtable diagnostics
    try {
      String memEntries = db.getProperty(cfHandle, "rocksdb.num-entries-active-mem-table");
      String memSize = db.getProperty(cfHandle, "rocksdb.cur-size-active-mem-table");
      String immMemEntries = db.getProperty(cfHandle, "rocksdb.num-entries-imm-mem-tables");
      System.out.println("Memtable state for this CF:");
      System.out.println("  Active memtable entries : " + memEntries);
      System.out.println("  Active memtable size    : " + memSize + " bytes");
      System.out.println("  Immutable memtable entries: " + immMemEntries);
      System.out.println();
    } catch (RocksDBException e) {
      System.out.println("(Could not read memtable properties: " + e.getMessage() + ")");
    }

    // Phase 1: read target key to prime the block cache
    resetAllCacheCounters(stats);

    byte[] value;
    try (ReadOptions ro = new ReadOptions()) {
      value = db.get(cfHandle, ro, targetKey);
    }

    long primeMiss = stats.getTickerCount(TickerType.BLOCK_CACHE_DATA_MISS);
    long primeHit = stats.getTickerCount(TickerType.BLOCK_CACHE_DATA_HIT);
    long totalMiss = stats.getTickerCount(TickerType.BLOCK_CACHE_MISS);
    long totalHit = stats.getTickerCount(TickerType.BLOCK_CACHE_HIT);
    long idxMiss = stats.getTickerCount(TickerType.BLOCK_CACHE_INDEX_MISS);
    long idxHit = stats.getTickerCount(TickerType.BLOCK_CACHE_INDEX_HIT);
    long filterMiss = stats.getTickerCount(TickerType.BLOCK_CACHE_FILTER_MISS);
    long filterHit = stats.getTickerCount(TickerType.BLOCK_CACHE_FILTER_HIT);

    boolean targetInMemtable = (value != null && totalMiss == 0 && totalHit == 0);

    System.out.println("Phase 1 — Read target key (prime cache):");
    if (value != null) {
      System.out.println("  Key EXISTS in DB. Value: " + value.length + " bytes");
    } else {
      System.out.println("  Key NOT FOUND in DB — bloom filters may skip data blocks entirely.");
    }
    System.out.println("  BLOCK_CACHE_DATA_MISS  : " + primeMiss);
    System.out.println("  BLOCK_CACHE_DATA_HIT   : " + primeHit);
    System.out.println("  BLOCK_CACHE_INDEX_MISS : " + idxMiss);
    System.out.println("  BLOCK_CACHE_INDEX_HIT  : " + idxHit);
    System.out.println("  BLOCK_CACHE_FILTER_MISS: " + filterMiss);
    System.out.println("  BLOCK_CACHE_FILTER_HIT : " + filterHit);
    System.out.println("  BLOCK_CACHE_TOTAL_MISS : " + totalMiss);
    System.out.println("  BLOCK_CACHE_TOTAL_HIT  : " + totalHit);
    if (targetInMemtable) {
      System.out.println("  --> Key was served from MEMTABLE (WAL replay), not from SST/block cache.");
    }
    System.out.println();

    // If target was in memtable, prime cache with the first neighbor instead
    if (targetInMemtable && !blockKeys.isEmpty()) {
      System.out.println("Phase 1b — Prime cache with first neighbor key (from SST):");
      resetAllCacheCounters(stats);

      byte[] firstNeighbor = blockKeys.get(0);
      try (ReadOptions ro = new ReadOptions()) {
        db.get(cfHandle, ro, firstNeighbor);
      }

      long p1bDataMiss = stats.getTickerCount(TickerType.BLOCK_CACHE_DATA_MISS);
      long p1bTotalMiss = stats.getTickerCount(TickerType.BLOCK_CACHE_MISS);
      long p1bTotalHit = stats.getTickerCount(TickerType.BLOCK_CACHE_HIT);
      System.out.println("  BLOCK_CACHE_DATA_MISS : " + p1bDataMiss + "  (block loaded from disk)");
      System.out.println("  BLOCK_CACHE_TOTAL_MISS: " + p1bTotalMiss);
      System.out.println("  BLOCK_CACHE_TOTAL_HIT : " + p1bTotalHit);
      System.out.println();
    }

    // Phase 2: read all neighbor keys and track per-key hits/misses
    byte[] firstNeighbor = blockKeys.isEmpty() ? null : blockKeys.get(0);
    List<byte[]> neighbors = new ArrayList<>();
    for (byte[] key : blockKeys) {
      if (!Arrays.equals(key, targetKey)
          && !(targetInMemtable && firstNeighbor != null && Arrays.equals(key, firstNeighbor))) {
        neighbors.add(key);
      }
    }

    if (neighbors.isEmpty()) {
      System.out.println("No neighbor keys to verify.");
      return;
    }

    resetAllCacheCounters(stats);

    int hitCount = 0;
    int missCount = 0;

    try (ReadOptions ro = new ReadOptions()) {
      for (byte[] neighborKey : neighbors) {
        long missBefore = stats.getTickerCount(TickerType.BLOCK_CACHE_DATA_MISS);
        db.get(cfHandle, ro, neighborKey);
        long missAfter = stats.getTickerCount(TickerType.BLOCK_CACHE_DATA_MISS);
        if (missAfter == missBefore) {
          hitCount++;
        } else {
          missCount++;
        }
      }
    }

    long totalNeighbors = neighbors.size();
    double hitRate = totalNeighbors > 0 ? (hitCount * 100.0 / totalNeighbors) : 0;

    System.out.println("Phase 2 — Read " + totalNeighbors + " neighbor keys:");
    System.out.println("  Cache hits  : " + hitCount + " / " + totalNeighbors);
    System.out.println("  Cache misses: " + missCount);
    System.out.printf("  Hit rate: %.1f%%%n", hitRate);
    System.out.println();

    if (missCount == 0) {
      System.out.println("PASS: All neighbor keys served from block cache.");
    } else {
      System.out.println("PARTIAL: " + missCount + " neighbor key(s) caused additional block cache misses.");
      System.out.println("  This can happen when keys span multiple data blocks or are in different LSM levels.");
    }
  }

  private static void resetAllCacheCounters(Statistics stats) {
    stats.getAndResetTickerCount(TickerType.BLOCK_CACHE_DATA_MISS);
    stats.getAndResetTickerCount(TickerType.BLOCK_CACHE_DATA_HIT);
    stats.getAndResetTickerCount(TickerType.BLOCK_CACHE_MISS);
    stats.getAndResetTickerCount(TickerType.BLOCK_CACHE_HIT);
    stats.getAndResetTickerCount(TickerType.BLOCK_CACHE_INDEX_MISS);
    stats.getAndResetTickerCount(TickerType.BLOCK_CACHE_INDEX_HIT);
    stats.getAndResetTickerCount(TickerType.BLOCK_CACHE_FILTER_MISS);
    stats.getAndResetTickerCount(TickerType.BLOCK_CACHE_FILTER_HIT);
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

  private record BlockResult(List<byte[]> keys, long blockNum, long totalBlocks, boolean exact) {}

  private BlockResult inspectBlockViaSstFileReader(
      String sstFilePath, byte[] targetKey) throws RocksDBException {
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

        return new BlockResult(blockKeys, blockIndex + 1, numDataBlocks, foundInFile);
      }
    }
  }

  // ---- sst_dump approach ----

  private BlockResult dumpAndParseBlocksViaSstDump(
      String sstFilePath, byte[] targetKey)
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
        return null;
      }

      return parseRawDump(tempFile, targetKey);
    } finally {
      Files.deleteIfExists(tempFile);
    }
  }

  private BlockResult parseRawDump(Path dumpFile, byte[] targetKey)
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
      return null;
    }

    System.out.println("Exact block: " + matchedBlockHeader);
    return new BlockResult(matchedBlockKeys, -1, totalBlocks, true);
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

  private int formatAccountFlatBlockResult(
      List<byte[]> blockKeys, byte[] targetKey, long blockNum, long totalBlocks, boolean exact) {

    System.out.println("=== RESULT: " + (exact ? "" : "Estimated ") + "accounts in same data block ===");
    if (blockNum > 0) {
      System.out.println("Block #" + blockNum + " of " + totalBlocks);
    }
    System.out.println("Total keys in block: " + blockKeys.size());
    System.out.println();

    String targetHex = HEX.formatHex(targetKey);

    for (byte[] key : blockKeys) {
      boolean isTarget = Arrays.equals(key, targetKey);
      String accHash = HEX.formatHex(key);
      System.out.println(
          (isTarget ? ">>> " : "    ") + "account_hash: " + accHash
              + (isTarget ? "  <-- TARGET" : ""));
    }
    System.out.println();

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
