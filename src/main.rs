mod bip39;

use clap::Parser;
use hex;
use ocl::builders::ContextProperties;
use ocl::enums::ArgVal;
use ocl::flags;
use ocl::prm::cl_ulong;
use ocl::core;
use rayon::prelude::*;
use std::ffi::CString;
use std::fs;
use std::str;

#[derive(Parser, Debug)]
#[command(
    author = "BIP39 Solver GPU",
    version = "0.2.0",
    about = "GPU-accelerated BIP39 mnemonic solver for Bitcoin P2SH-P2WPKH addresses"
)]
struct Args {
    /// Target Bitcoin Base58 address (e.g. 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy)
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

    let raw_words: Vec<&str> = file_content.split_whitespace().collect();
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

    // 3. Compute Base Entropy and Missing Bit Count
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

    // 4. Load OpenCL Kernels
    let kernel_name = "int_to_address".to_string();
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

    // 5. Initialize OpenCL Devices
    let platform_id = match core::default_platform() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("OpenCL Error: No default platform found ({})", e);
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

    println!("Found {} OpenCL device(s). Starting solver...", device_ids.len());

    let batch_size = args.batch_size;

    // 6. Run GPU Solver across available devices
    device_ids.into_par_iter().for_each(move |device_id| {
        if let Err(e) = mnemonic_gpu(
            platform_id,
            device_id,
            src_cstring.clone(),
            &kernel_name,
            target_addr_bytes,
            start_entropy,
            total_space,
            batch_size,
        ) {
            eprintln!("GPU execution error: {}", e);
        }
    });
}

fn mnemonic_gpu(
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

        if mnemonic_found[0] == 0x01 {
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

    Ok(())
}
