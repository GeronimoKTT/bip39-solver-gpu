# BIP39 Solver GPU

A modernized, high-performance GPU-accelerated BIP39 mnemonic solver for Bitcoin P2SH-P2WPKH addresses.

## Features & Modes

### 1. Multi-Address TSV & Single Address Support
The `--address` parameter supports both:
- A single Base58 Bitcoin address (`--address 3Co6PmCofnGXHwPR946YTXqJxCoL1TQXHb`)
- A **`.tsv` or `.txt` address file** containing thousands of target addresses and balances (`--address sample_addresses.tsv`).
All target addresses in the `.tsv` file are Base58-decoded into raw 25-byte buffers and pre-loaded directly into GPU global memory prior to searching.

### 2. Permutation Mode (Unordered 12 Words)
If you know all 12 words of a BIP39 seed phrase but do **not know their exact order**, pass a file containing the 12 words without `?` wildcards.
- The solver automatically generates all $12! = 479,001,600$ permutations in parallel.
- Validates BIP39 4-bit checksums on the host CPU using Rayon multi-threading to filter out invalid combinations.
- Parallel-evaluates valid candidate seed permutations on GPU devices against all loaded target addresses in GPU memory.

### 3. Wildcard Range Mode (Missing Words)
If you know a portion of your 12-word seed in order (e.g. 8 to 11 words) and are missing the remaining words:
- Replace missing word positions with `?` in your word file.
- The solver iterates through the missing entropy search space on GPU devices to find the matching mnemonic phrase.

---

## Usage

### 1. Build
```bash
cargo build --release
```

### 2. Run Permutation Mode (Single Address)
```bash
./target/release/bip39-solver-gpu \
  --address 3Co6PmCofnGXHwPR946YTXqJxCoL1TQXHb \
  --file sample_shuffled.txt
```

### 3. Run with Multi-Address TSV File
```bash
./target/release/bip39-solver-gpu \
  --address sample_addresses.tsv \
  --file sample_shuffled.txt
```

### Command Line Options
- `-a, --address <ADDRESS>`: Single Target Bitcoin Base58 address OR path to `.tsv`/`.txt` file containing address and balance columns.
- `-f, --file <FILE>`: Path to text file containing 12 words (separated by spaces or newlines). Use `?` for missing words.
- `-b, --batch-size <BATCH_SIZE>`: Batch size per GPU kernel iteration (default: `10000000`).
- `-h, --help`: Print help information.