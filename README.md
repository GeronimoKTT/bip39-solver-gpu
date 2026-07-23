# BIP39 Solver GPU

A modernized, high-performance GPU-accelerated BIP39 mnemonic solver & random seed scanner for Bitcoin P2SH-P2WPKH addresses.

## Features & Modes

### 1. GPU Random Seed Scanner Mode (`--file auto --address <tsv/txt>`)
When passing `--file auto` together with an address file (`--address sample_addresses.tsv` or `.txt`), the tool launches **GPU Random Seed Scanner Mode**:
- Loads all target addresses into GPU memory (`target_addresses` buffer).
- Continuously auto-generates random valid BIP39 12-word seeds in batches (e.g. 10,000,000 per GPU execution batch).
- Derives P2SH Bitcoin addresses directly on GPU CUDA cores and compares each against all target addresses loaded in GPU memory.
- When any generated seed matches any address in your file, it outputs the winning mnemonic and exits!

### 2. Single-Seed Auto Test Mode (`--file auto`)
When passing `--file auto` without a custom address (or `--address auto`), it generates a **single random valid 12-word BIP39 seed phrase**:
- Derives its target P2SH address.
- Shuffles the 12 words.
- Runs Permutation Mode to recover the original seed phrase as a benchmark test.

### 3. Multi-Address TSV & Single Address Support
The `--address` parameter supports:
- A single Base58 Bitcoin address (`--address 3Co6PmCofnGXHwPR946YTXqJxCoL1TQXHb`)
- A **`.tsv` or `.txt` address file** (`--address sample_addresses.tsv`) with address and balance columns.

### 4. Permutation Mode (Unordered 12 Words)
If you know all 12 words of a BIP39 seed phrase but do **not know their exact order**, pass a file containing the 12 words without `?` wildcards.
- Generates all $12! = 479,001,600$ permutations in parallel across CPU cores.
- Validates BIP39 4-bit checksums on host CPU using Rayon multi-threading to filter out invalid combinations.
- Parallel-evaluates valid candidate seed permutations on GPU devices against all loaded target addresses in GPU memory.

### 5. Wildcard Range Mode (Missing Words)
If you know a portion of your 12-word seed in order (e.g. 8 to 11 words) and are missing the remaining words:
- Replace missing word positions with `?` in your word file.
- The solver iterates through the missing entropy search space on GPU devices to find the matching mnemonic phrase.

---

## Usage

### 1. Build
```bash
cargo build --release
```

### 2. GPU Random Seed Scanner Mode (Multi-Address TSV)
```bash
./target/release/bip39-solver-gpu \
  --file auto \
  --address sample_addresses.tsv
```

### 3. Auto-Generate & Benchmark Single Seed
```bash
./target/release/bip39-solver-gpu --file auto
```

### 4. Permutation Mode (Unordered 12 Words)
```bash
./target/release/bip39-solver-gpu \
  --address 3Co6PmCofnGXHwPR946YTXqJxCoL1TQXHb \
  --file sample_shuffled.txt
```

### Command Line Options
- `-a, --address <ADDRESS>`: Target Bitcoin Base58 address, `.tsv`/`.txt` file, or `auto` (default: `auto`).
- `-f, --file <FILE>`: Path to 12-word text file, OR `auto` for random seed generation / GPU scanner mode.
- `-b, --batch-size <BATCH_SIZE>`: Batch size per GPU kernel iteration (default: `10000000`).
- `-h, --help`: Print help information.