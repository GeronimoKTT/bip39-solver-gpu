use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let search_paths = [
        "/usr/local/cuda/lib64",
        "/usr/local/cuda/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
    ];

    let out_dir = env::var("OUT_DIR").unwrap();
    let mut found = false;

    for path in &search_paths {
        let p = Path::new(path);
        let opencl_so = p.join("libOpenCL.so");
        let opencl_so_1 = p.join("libOpenCL.so.1");

        if opencl_so.exists() {
            println!("cargo:rustc-link-search=native={}", path);
            found = true;
            break;
        } else if opencl_so_1.exists() {
            // Create symlink libOpenCL.so -> libOpenCL.so.1 in OUT_DIR
            let target_symlink = Path::new(&out_dir).join("libOpenCL.so");
            let _ = fs::remove_file(&target_symlink);
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&opencl_so_1, &target_symlink);

            println!("cargo:rustc-link-search=native={}", out_dir);
            found = true;
            break;
        }
    }

    if !found {
        println!("cargo:warning=libOpenCL.so not found in standard system/CUDA search paths.");
    }
}
