# RocksDB Block Content Inspector for Besu

A standalone tool that reveals **which storage keys share the same RocksDB data block** when Besu reads a contract storage slot from its flat database.

## Why this matters

When Besu performs an `SLOAD` (contract storage read), the Bonsai flat database resolves it with a **single RocksDB `Get()`**. RocksDB does not read individual keys from disk — it reads entire **data blocks** (~32 KiB by default in Besu). Every other key packed into that same block is loaded into the **block cache** as a side effect.

This tool lets you:
- Pick any contract address + storage slot
- Find the exact SST file and data block that contains it
- List **all other keys** that get cached alongside it for free

This is useful for understanding cache locality, predicting cache hit rates, and analyzing storage access patterns on Besu nodes.

## How Besu encodes flat-DB storage keys

The flat storage lives in the `ACCOUNT_STORAGE_STORAGE` column family (RocksDB CF id `0x08`). Each key is 64 bytes:

```
key = keccak256(address) || keccak256(slot_as_uint256)
      ├── 32 bytes ──────┤├── 32 bytes ────────────────┤
```

- **address**: the 20-byte contract address
- **slot**: the storage slot index, left-padded to 32 bytes (uint256), then keccak256-hashed

This tool replicates that exact encoding so it can look up the right key in RocksDB.

## Prerequisites

- **JDK 21+**
- A **copy of the Besu RocksDB data directory**, or stop the Besu node before running (RocksDB locks the directory)
- *(Optional)* **`sst_dump`** from RocksDB 9.7.x for exact block boundaries (see `--use-sst-dump` flag)

By default the tool uses `SstFileReader` from `rocksdbjni` — **no external binary needed**.

## Build

```bash
git clone https://github.com/ahamlat/Rocksdb-block-content.git
cd Rocksdb-block-content
./gradlew build
```

## Usage

```bash
./gradlew run --args='--db-path /data/besu/database \
  --address 0xdAC17F958D2ee523a2206206994597C13D831ec7 \
  --slot 0x2'
```

### Options

| Flag | Required | Description |
|------|----------|-------------|
| `--db-path` | Yes | Path to the Besu RocksDB database directory |
| `--address` | Yes* | Contract address (hex with 0x prefix) |
| `--slot` | Yes* | Storage slot index (hex with 0x prefix, or decimal) |
| `--raw-key` | No | Pre-computed 64-byte key (128 hex chars) — use instead of address+slot |
| `--use-sst-dump` | No | Use external `sst_dump` binary for exact block boundaries |
| `--sst-dump-path` | No | Path to the `sst_dump` binary (default: `sst_dump` on PATH) |

\* Not required if `--raw-key` is provided.

### Example output

```
=== Besu Flat-DB SST Block Inspector ===
Target key (128 hex): 5b7f...a3c1
  account hash : 5b7f...
  slot hash    : a3c1...

Column family ACCOUNT_STORAGE_STORAGE (0x08) found.
Key EXISTS in flat DB. Value (32 bytes): 0000...0001

Found 847 SST files for ACCOUNT_STORAGE_STORAGE CF.
SST file containing key: /data/besu/database/000532.sst

Running sst_dump --command=raw on /data/besu/database/000532.sst ...

SST file stats: 1204 data blocks, 38521 total keys

=== RESULT: Keys in the same data block as target ===
Block: Data Block # 417 @ 0x00D3A000 size 32611
Total keys in block: 32

    5b7e...9f01
        account_hash=5b7e... slot_hash=9f01...
>>> 5b7f...a3c1 <-- TARGET
        account_hash=5b7f... slot_hash=a3c1...
    5b80...b2e7
        account_hash=5b80... slot_hash=b2e7...
    ...

When Besu reads this storage slot from the flat DB, RocksDB loads the
entire ~32KiB data block above into the block cache. All 32 keys
become cached as a side effect of that single Get().
```

## How it works

1. **Computes the 64-byte flat-DB key** using the same encoding as Besu's `BonsaiFlatDbStrategy`: `keccak256(address) || keccak256(slot)`
2. **Opens the RocksDB database read-only** and locates the `ACCOUNT_STORAGE_STORAGE` column family (id `0x08`)
3. **Verifies the key exists** with a `Get()` call
4. **Finds the SST file** using `getLiveFilesMetaData()` — selects the file whose key range contains the target
5. **Lists co-block keys** using one of two approaches:
   - *(default)* Opens the SST with `SstFileReader`, reads `TableProperties` (number of data blocks, entries), computes entries-per-block, and locates the block region containing the target key — **no external binary needed**
   - *(with `--use-sst-dump`)* Runs `sst_dump --command=raw` for exact block boundaries parsed from the dump output

## Reference

- Besu flat-DB key encoding: [`BonsaiFlatDbStrategy.java`](https://github.com/hyperledger/besu/blob/main/ethereum/core/src/main/java/org/hyperledger/besu/ethereum/trie/pathbased/bonsai/storage/flat/BonsaiFlatDbStrategy.java)
- Besu block size config: [`RocksDBColumnarKeyValueStorage.java`](https://github.com/hyperledger/besu/blob/main/plugins/rocksdb/src/main/java/org/hyperledger/besu/plugin/services/storage/rocksdb/segmented/RocksDBColumnarKeyValueStorage.java) (`ROCKSDB_BLOCK_SIZE = 32768`)
- RocksDB `sst_dump` tool: [RocksDB Wiki](https://github.com/facebook/rocksdb/wiki/Administration-and-Data-Access-Tool)

## License

Apache 2.0
