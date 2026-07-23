# BIP39 Solver GPU

A modernized, high-performance GPU-accelerated BIP39 mnemonic solver for Bitcoin P2SH-P2WPKH addresses.

## Features & Modes

### 1. Auto-Generation Mode (`--file auto`)
Passing `--file auto` generates a **random, cryptographically secure 12-word BIP39 seed phrase** (with standard 4-bit SHA256 checksum) as used by real Bitcoin wallets.
- Derives the corresponding target P2SH Bitcoin address (`m/49'/0'/0'/0/0`) via OpenCL GPU kernel.
- Randomly shuffles the 12 words.
- Automatically launches the GPU solver to benchmark recovering the original seed phrase.

### 2. Multi-Address TSV & Single Address Support
The `--address` parameter supports:
- A single Base58 Bitcoin address (`--address 3Co6PmCofnGXHwPR946YTXqJxCoL1TQXHb`)
- A **`.tsv` or `.txt` address file** (`--address sample_addresses.tsv`) with address and balance columns.
- `auto` (`--address auto`), which defaults to the derived target address of `--file auto`.

### 3. Permutation Mode (Unordered 12 Words)
If you know all 12 words of a BIP39 seed phrase but do **not know their exact order**, pass a file containing the 12 words without `?` wildcards.
- Generates all $12! = 479,001,600$ permutations in parallel across CPU cores.
- Validates BIP39 4-bit checksums on host CPU using Rayon multi-threading to filter out invalid combinations.
- Parallel-evaluates valid candidate seed permutations on GPU devices against all loaded target addresses in GPU memory.

### 4. Wildcard Range Mode (Missing Words)
If you know a portion of your 12-word seed in order (e.g. 8 to 11 words) and are missing the remaining words:
- Replace missing word positions with `?` in your word file.
- The solver iterates through the missing entropy search space on GPU devices to find the matching mnemonic phrase.

---

## Usage

### 1. Build
```bash
cargo build --release
```

### 2. Auto-Generate & Test Random 12-Word Seed
```bash
./target/release/bip39-solver-gpu --file auto
```

### 3. Run Permutation Mode (Single Address)
```bash
./target/release/bip39-solver-gpu \
  --address 3Co6PmCofnGXHwPR946YTXqJxCoL1TQXHb \
  --file sample_shuffled.txt
```

### 4. Run with Multi-Address TSV File
```bash
./target/release/bip39-solver-gpu \
  --address sample_addresses.tsv \
  --file sample_shuffled.txt
```

### Command Line Options
- `-a, --address <ADDRESS>`: Target Bitcoin Base58 address, `.tsv`/`.txt` file, or `auto` (default: `auto`).
- `-f, --file <FILE>`: Path to 12-word text file, OR `auto` to generate a random 12-word seed.
- `-b, --batch-size <BATCH_SIZE>`: Batch size per GPU kernel iteration (default: `10000000`).
- `-h, --help`: Print help information.