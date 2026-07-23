mod bip39;

use clap::Parser;
use hex;
use indicatif::{ProgressBar, ProgressStyle};
use ocl::builders::ContextProperties;
use ocl::enums::ArgVal;
use ocl::flags;
use ocl::prm::cl_ulong;
use ocl::core;
use rayon::prelude::*;
use std::ffi::CString;
use std::fs;
use std::str;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Parser, Debug)]
#[command(
    author = "BIP39 Solver GPU",
    version = "0.2.0",
    about = "GPU-accelerated BIP39 mnemonic solver for Bitcoin P2SH-P2WPKH addresses"
)]
struct Args {
    /// Target Bitcoin Base58 address (e.g. 3Co6PmCofnGXHwPR946YTXqJxCoL1TQXHb)
    #[arg(short, long)]
    address: String,

    /// Path to text file containing 12 words (separated by spaces or newlines). Use '?' for missing words.
    #[arg(short, long)]
    file: String,

    /// Batch size per GPU kernel execution
    #[arg(short, long, default_value_t = 10_000_000)]
    batch_size: u64,
}

fn main() {
    let args = Args::parse();

    // 1. Decode Target Address from Base58Check
    let target_addr_bytes = match bs58::decode(&args.address).into_vec() {
        Ok(b) if b.len() == 25 => {
            let mut arr = [0u8; 25];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            eprintln!("Error: Base58 decoded target address is {} bytes (expected 25 bytes)", b.len());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: Invalid Base58 address '{}': {}", args.address, e);
            std::process::exit(1);
        }
    };

    println!("Target Address: {}", args.address);
    println!("Target Address Bytes (hex): {}", hex::encode(&target_addr_bytes));

    // 2. Load and Parse 12-Word List File
    let file_content = fs::read_to_string(&args.file).unwrap_or_else(|e| {
        eprintln!("Error reading file '{}': {}", args.file, e);
        std::process::exit(1);
    });

    let raw_words: Vec<&str> = file_content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .flat_map(|line| line.split_whitespace())
        .collect();

    if raw_words.is_empty() {
        eprintln!("Error: Wordlist file '{}' is empty", args.file);
        std::process::exit(1);
    }

    let mut words = Vec::new();
    for i in 0..12 {
        if i < raw_words.len() {
            words.push(raw_words[i]);
        } else {
            words.push("?");
        }
    }

    println!("Input Words (12): {:?}", words);

    let has_wildcards = words.iter().any(|&w| w == "?" || w == "*" || w == "x");

    // 3. Load OpenCL Program Source
    let cl_files = [
        "common",
        "ripemd",
        "sha2",
        "secp256k1_common",
        "secp256k1_scalar",
        "secp256k1_field",
        "secp256k1_group",
        "secp256k1_prec",
        "secp256k1",
        "address",
        "mnemonic_constants",
        "int_to_address",
    ];

    let mut raw_cl_file = String::new();
    for file in &cl_files {
        let file_path = format!("./cl/{}.cl", file);
        let file_str = fs::read_to_string(&file_path).unwrap_or_else(|_| {
            fs::read_to_string(format!("cl/{}.cl", file)).unwrap_or_else(|e| {
                eprintln!("Error reading kernel file '{}.cl': {}", file, e);
                std::process::exit(1);
            })
        });
        raw_cl_file.push_str(&file_str);
        raw_cl_file.push_str("\n");
    }

    let src_cstring = CString::new(raw_cl_file).unwrap();

    let platform_id = match core::default_platform() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\n❌ OpenCL Error: No default platform found ({})", e);
            eprintln!("\n💡 TROUBLESHOOTING OPENCL ON NVIDIA / CUDA CONTAINERS:");
            eprintln!("--------------------------------------------------------------------------------");
            eprintln!("1. Enable NVIDIA OpenCL ICD inside your container:");
            eprintln!("   mkdir -p /etc/OpenCL/vendors && echo \"libnvidia-opencl.so.1\" > /etc/OpenCL/vendors/nvidia.icd");
            eprintln!("2. If running Docker, make sure you started it with `--gpus all`:");
            eprintln!("   docker run --gpus all -it ...");
            eprintln!("3. Install OpenCL ICD packages if missing:");
            eprintln!("   apt-get update && apt-get install -y ocl-icd-opencl-dev clinfo");
            eprintln!("4. Test OpenCL detection using:");
            eprintln!("   clinfo");
            eprintln!("--------------------------------------------------------------------------------\n");
            std::process::exit(1);
        }
    };

    let device_ids = match core::get_device_ids(&platform_id, Some(ocl::flags::DEVICE_TYPE_GPU), None) {
        Ok(ids) if !ids.is_empty() => ids,
        _ => match core::get_device_ids(&platform_id, Some(ocl::flags::DEVICE_TYPE_ALL), None) {
            Ok(ids) => ids,
            Err(e) => {
                eprintln!("OpenCL Error: No OpenCL devices found ({})", e);
                std::process::exit(1);
            }
        },
    };

    println!("\nFound {} OpenCL device(s).", device_ids.len());
    for (idx, dev) in device_ids.iter().enumerate() {
        let name = core::get_device_info(dev, ocl::core::DeviceInfo::Name)
            .map(|info| info.to_string())
            .unwrap_or_else(|_| "GPU Device".to_string());
        println!("  [GPU {}] Device Name: {}", idx, name);
    }

    if !has_wildcards {
        // MODE 1: PERMUTATION MODE (12 known words, unordered)
        println!("\n=== Running Mode: PERMUTATION MODE ===");
        println!("Generating and filtering permutations in parallel across CPU cores...");

        let candidate_pairs = generate_permutation_candidates_parallel(&words);
        println!("Found {} valid BIP39 checksum candidates. Dispatching to GPU for address matching...", candidate_pairs.len());

        let (hi_list, lo_list): (Vec<u64>, Vec<u64>) = candidate_pairs.into_iter().unzip();
        let batch_size = args.batch_size;
        let kernel_name = "int_to_address_perm";

        device_ids.into_par_iter().for_each(move |device_id| {
            if let Err(e) = mnemonic_gpu_perm(
                platform_id,
                device_id,
                src_cstring.clone(),
                kernel_name,
                target_addr_bytes,
                &hi_list,
                &lo_list,
                batch_size,
            ) {
                eprintln!("GPU Execution Error: {}", e);
            }
        });
    } else {
        // MODE 2: WILDCARD RANGE MODE (Some words unknown '?')
        println!("\n=== Running Mode: WILDCARD RANGE MODE ===");

        let mut start_entropy: u128 = 0;
        let mut missing_entropy_bits: u32 = 0;

        for (i, &word) in words.iter().enumerate() {
            if let Some(idx) = bip39::get_word_index(word) {
                let idx = idx as u128;
                let shift = match i {
                    0 => 117,
                    1 => 106,
                    2 => 95,
                    3 => 84,
                    4 => 73,
                    5 => 62,
                    6 => 51,
                    7 => 40,
                    8 => 29,
                    9 => 18,
                    10 => 7,
                    11 => 0,
                    _ => unreachable!(),
                };
                if i == 11 {
                    start_entropy |= (idx >> 4) << shift;
                } else {
                    start_entropy |= idx << shift;
                }
            } else {
                let bits = if i == 11 { 7 } else { 11 };
                missing_entropy_bits += bits;
            }
        }

        let total_space: u64 = if missing_entropy_bits >= 64 {
            u64::MAX
        } else {
            1u64 << missing_entropy_bits
        };

        println!("Missing entropy bits: {}", missing_entropy_bits);
        println!("Total search space: {} combinations", total_space);
        println!("Batch size: {}", args.batch_size);

        let kernel_name = "int_to_address";
        let batch_size = args.batch_size;

        device_ids.into_par_iter().for_each(move |device_id| {
            if let Err(e) = mnemonic_gpu_range(
                platform_id,
                device_id,
                src_cstring.clone(),
                kernel_name,
                target_addr_bytes,
                start_entropy,
                total_space,
                batch_size,
            ) {
                eprintln!("GPU Execution Error: {}", e);
            }
        });
    }
}

/// Simple Sha256 helper for host-side checksum validation
fn simple_sha256(data: &[u8]) -> [u8; 32] {
    use std::num::Wrapping;

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h = [
        Wrapping(0x6a09e667u32),
        Wrapping(0xbb67ae85u32),
        Wrapping(0x3c6ef372u32),
        Wrapping(0xa54ff53au32),
        Wrapping(0x510e527fu32),
        Wrapping(0x9b05688cu32),
        Wrapping(0x1f83d9abu32),
        Wrapping(0x5be0cd19u32),
    ];

    let mut block = [0u8; 64];
    block[..data.len()].copy_from_slice(data);
    block[data.len()] = 0x80;
    let bit_len = (data.len() as u64) * 8;
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());

    let mut w = [Wrapping(0u32); 64];
    for i in 0..16 {
        w[i] = Wrapping(u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]));
    }
    for i in 16..64 {
        let s0 = (w[i - 15] >> 7 | w[i - 15] << 25) ^ (w[i - 15] >> 18 | w[i - 15] << 14) ^ (w[i - 15] >> 3);
        let s1 = (w[i - 2] >> 17 | w[i - 2] << 15) ^ (w[i - 2] >> 19 | w[i - 2] << 13) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_var = h[7];

    for i in 0..64 {
        let s1_val = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h_var + s1_val + ch + Wrapping(k[i]) + w[i];
        let s0_val = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0_val + maj;

        h_var = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_var;

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].0.to_be_bytes());
    }
    out
}

fn generate_permutation_candidates_parallel(words: &[&str]) -> Vec<(u64, u64)> {
    let word_indices: Vec<u16> = words
        .iter()
        .map(|w| bip39::get_word_index(w).unwrap_or_else(|| {
            eprintln!("Error: Unknown BIP39 word '{}'", w);
            std::process::exit(1);
        }) as u16)
        .collect();

    let total_perms: u64 = 479_001_600; // 12!
    let pb = ProgressBar::new(total_perms);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[CPU Prep] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, ETA {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let progress_counter = AtomicU64::new(0);

    // Parallelize over the 12 choices for the first position
    let candidate_chunks: Vec<Vec<(u64, u64)>> = (0..12)
        .into_par_iter()
        .map(|first_idx| {
            let mut sub_indices = Vec::with_capacity(11);
            for (idx, &w) in word_indices.iter().enumerate() {
                if idx != first_idx {
                    sub_indices.push(w);
                }
            }
            sub_indices.sort_unstable();

            let mut local_candidates = Vec::new();
            let mut perm_count = 0u64;

            loop {
                let mut current_perm = [0u16; 12];
                current_perm[0] = word_indices[first_idx];
                current_perm[1..].copy_from_slice(&sub_indices);

                let mut entropy_128: u128 = 0;
                for (i, &idx) in current_perm.iter().take(11).enumerate() {
                    let shift = 117 - i * 11;
                    entropy_128 |= (idx as u128) << shift;
                }
                entropy_128 |= (current_perm[11] >> 4) as u128;

                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&entropy_128.to_be_bytes());

                let sha_res = simple_sha256(&bytes);
                let expected_checksum = (sha_res[0] >> 4) & 0x0F;
                let actual_checksum = (current_perm[11] & 0x0F) as u8;

                if expected_checksum == actual_checksum {
                    let hi = (entropy_128 >> 64) as u64;
                    let lo = (entropy_128 & 0xFFFF_FFFF_FFFF_FFFF) as u64;
                    local_candidates.push((hi, lo));
                }

                perm_count += 1;
                if perm_count % 100_000 == 0 {
                    progress_counter.fetch_add(100_000, Ordering::Relaxed);
                }

                if !next_permutation(&mut sub_indices) {
                    break;
                }
            }

            local_candidates
        })
        .collect();

    pb.finish_with_message("Permutation pre-filtering complete.");

    candidate_chunks.into_iter().flatten().collect()
}

fn next_permutation<T: Ord>(arr: &mut [T]) -> bool {
    if arr.len() <= 1 {
        return false;
    }
    let mut i = arr.len() - 1;
    while i > 0 && arr[i - 1] >= arr[i] {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    let mut j = arr.len() - 1;
    while arr[j] <= arr[i - 1] {
        j -= 1;
    }
    arr.swap(i - 1, j);
    arr[i..].reverse();
    true
}

fn mnemonic_gpu_perm(
    platform_id: core::types::abs::PlatformId,
    device_id: core::types::abs::DeviceId,
    src: CString,
    kernel_name: &str,
    target_addr_bytes: [u8; 25],
    hi_list: &[u64],
    lo_list: &[u64],
    batch_size: u64,
) -> ocl::core::Result<()> {
    let context_properties = ContextProperties::new().platform(platform_id);
    let context = core::create_context(Some(&context_properties), &[device_id], None, None)?;
    let program = core::create_program_with_source(&context, &[src])?;
    core::build_program(&program, Some(&[device_id]), &CString::new("")?, None, None)?;
    let queue = core::create_command_queue(&context, &device_id, None)?;

    let target_address_buf = unsafe {
        core::create_buffer(
            &context,
            flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR,
            25,
            Some(&target_addr_bytes),
        )?
    };

    let total_candidates = hi_list.len();
    let pb = ProgressBar::new(total_candidates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[GPU Process] [{elapsed_precise}] [{bar:40.green/blue}] {pos}/{len} ({per_sec}, ETA {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut offset = 0;

    while offset < total_candidates {
        let chunk_len = std::cmp::min(batch_size as usize, total_candidates - offset);
        let hi_chunk = &hi_list[offset..offset + chunk_len];
        let lo_chunk = &lo_list[offset..offset + chunk_len];

        let hi_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR,
                chunk_len,
                Some(hi_chunk),
            )?
        };

        let lo_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR,
                chunk_len,
                Some(lo_chunk),
            )?
        };

        let mut target_mnemonic = vec![0u8; 120];
        let mut mnemonic_found = vec![0u8; 1];

        let target_mnemonic_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                120,
                Some(&target_mnemonic),
            )?
        };

        let mnemonic_found_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                1,
                Some(&mnemonic_found),
            )?
        };

        let kernel = core::create_kernel(&program, kernel_name)?;

        core::set_kernel_arg(&kernel, 0, ArgVal::mem(&hi_buf))?;
        core::set_kernel_arg(&kernel, 1, ArgVal::mem(&lo_buf))?;
        core::set_kernel_arg(&kernel, 2, ArgVal::mem(&target_address_buf))?;
        core::set_kernel_arg(&kernel, 3, ArgVal::mem(&target_mnemonic_buf))?;
        core::set_kernel_arg(&kernel, 4, ArgVal::mem(&mnemonic_found_buf))?;

        unsafe {
            core::enqueue_kernel(
                &queue,
                &kernel,
                1,
                None,
                &[chunk_len, 1, 1],
                None,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        unsafe {
            core::enqueue_read_buffer(
                &queue,
                &target_mnemonic_buf,
                true,
                0,
                &mut target_mnemonic,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        unsafe {
            core::enqueue_read_buffer(
                &queue,
                &mnemonic_found_buf,
                true,
                0,
                &mut mnemonic_found,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        pb.inc(chunk_len as u64);

        if mnemonic_found[0] == 0x01 {
            pb.finish_with_message("MATCH FOUND!");
            let s = String::from_utf8_lossy(&target_mnemonic).to_string();
            let mnemonic = s.trim_matches(char::from(0));
            println!("\n========================================");
            println!("🎉 MNEMONIC PERMUTATION FOUND!");
            println!("Mnemonic: {}", mnemonic);
            println!("========================================\n");
            std::process::exit(0);
        }

        offset += chunk_len;
    }

    pb.finish_with_message("GPU processing finished.");
    Ok(())
}

fn mnemonic_gpu_range(
    platform_id: core::types::abs::PlatformId,
    device_id: core::types::abs::DeviceId,
    src: CString,
    kernel_name: &str,
    target_addr_bytes: [u8; 25],
    start_entropy: u128,
    total_space: u64,
    batch_size: u64,
) -> ocl::core::Result<()> {
    let context_properties = ContextProperties::new().platform(platform_id);
    let context = core::create_context(Some(&context_properties), &[device_id], None, None)?;
    let program = core::create_program_with_source(&context, &[src])?;
    core::build_program(&program, Some(&[device_id]), &CString::new("")?, None, None)?;
    let queue = core::create_command_queue(&context, &device_id, None)?;

    let target_address_buf = unsafe {
        core::create_buffer(
            &context,
            flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR,
            25,
            Some(&target_addr_bytes),
        )?
    };

    let pb = ProgressBar::new(total_space);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[GPU Range Search] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, ETA {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut current_offset: u128 = 0;
    let max_offset = total_space as u128;

    while current_offset < max_offset {
        let current_batch = std::cmp::min(batch_size, (max_offset - current_offset) as u64);
        let start = start_entropy | current_offset;
        let start_hi: cl_ulong = (start >> 64) as u64;
        let start_lo: cl_ulong = (start & 0xFFFF_FFFF_FFFF_FFFF) as u64;

        let mut target_mnemonic = vec![0u8; 120];
        let mut mnemonic_found = vec![0u8; 1];

        let target_mnemonic_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                120,
                Some(&target_mnemonic),
            )?
        };

        let mnemonic_found_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                1,
                Some(&mnemonic_found),
            )?
        };

        let kernel = core::create_kernel(&program, kernel_name)?;

        core::set_kernel_arg(&kernel, 0, ArgVal::scalar(&start_hi))?;
        core::set_kernel_arg(&kernel, 1, ArgVal::scalar(&start_lo))?;
        core::set_kernel_arg(&kernel, 2, ArgVal::mem(&target_address_buf))?;
        core::set_kernel_arg(&kernel, 3, ArgVal::mem(&target_mnemonic_buf))?;
        core::set_kernel_arg(&kernel, 4, ArgVal::mem(&mnemonic_found_buf))?;

        unsafe {
            core::enqueue_kernel(
                &queue,
                &kernel,
                1,
                None,
                &[current_batch as usize, 1, 1],
                None,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        unsafe {
            core::enqueue_read_buffer(
                &queue,
                &target_mnemonic_buf,
                true,
                0,
                &mut target_mnemonic,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        unsafe {
            core::enqueue_read_buffer(
                &queue,
                &mnemonic_found_buf,
                true,
                0,
                &mut mnemonic_found,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        pb.inc(current_batch);

        if mnemonic_found[0] == 0x01 {
            pb.finish_with_message("MATCH FOUND!");
            let s = String::from_utf8_lossy(&target_mnemonic).to_string();
            let mnemonic = s.trim_matches(char::from(0));
            println!("\n========================================");
            println!("🎉 MNEMONIC FOUND!");
            println!("Mnemonic: {}", mnemonic);
            println!("========================================\n");
            std::process::exit(0);
        }

        current_offset += current_batch as u128;
    }

    pb.finish_with_message("GPU Range Search complete.");
    Ok(())
}
