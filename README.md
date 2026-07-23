# BIP39 Solver GPU

A modernized, high-performance GPU-accelerated BIP39 mnemonic solver for Bitcoin P2SH-P2WPKH addresses.

## Features & Improvements
- **Modernized Dependencies**: Updated to Rust Edition 2021 with modern crates (`clap`, `bs58`, `rayon`, `ocl`, `hex`). Removed legacy dependencies (`openssl-sys`, `rustc-serialize`, outdated custom crates).
- **Standalone General Tool**: Removed hardcoded target transactions and old web server calls.
- **Dynamic Address Input**: Pass any target Base58 Bitcoin address via `--address`.
- **Flexible Wordlist File Input**: Pass a text file containing 12 words via `--file`. Use `?` for missing words.

## Usage

### 1. Build
```bash
cargo build --release
```

### 2. Run
```bash
./target/release/bip39-solver-gpu --address <TARGET_ADDRESS> --file <PATH_TO_WORDS_FILE>
```

### Command Line Options
- `-a, --address <ADDRESS>`: Target Bitcoin Base58 address (e.g. `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy`)
- `-f, --file <FILE>`: Path to text file containing 12 words (separated by spaces or newlines). Use `?` for missing words.
- `-b, --batch-size <BATCH_SIZE>`: Batch size per GPU kernel iteration (default: `10000000`)
- `-h, --help`: Print help information

### Example `words.txt`
```text
abandon
ability
able
about
above
absent
absorb
abstract
?
?
?
?
```