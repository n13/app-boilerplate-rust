use image::{ImageFormat, ImageReader, Pixel};

fn main() {
    println!("cargo:rerun-if-changed=script.ld");
    println!("cargo:rerun-if-changed=icons/crab_14x14.gif");
    println!("cargo:rerun-if-changed=icons/mask_14x14.gif");
    println!("cargo:rerun-if-changed=src/ml-dsa-c");

    // Process icon
    let path = std::path::PathBuf::from("icons");
    let reader = ImageReader::open(path.join("crab_14x14.gif")).unwrap();
    let img = reader.decode().unwrap();
    let mut gray = img.into_luma8();

    // Apply mask
    let mask = ImageReader::open(path.join("mask_14x14.gif"))
        .unwrap()
        .decode()
        .unwrap()
        .into_luma8();

    for (x, y, mask_pixel) in mask.enumerate_pixels() {
        let mask_value = mask_pixel[0];
        let mut gray_pixel = *gray.get_pixel(x, y);
        if mask_value == 0 {
            gray_pixel = image::Luma([0]);
        } else {
            gray_pixel.invert();
        }
        gray.put_pixel(x, y, gray_pixel);
    }

    let glyph_path = std::path::PathBuf::from("glyphs");
    gray.save_with_format(glyph_path.join("home_nano_nbgl.png"), ImageFormat::Png)
        .unwrap();

    // Compile ML-DSA C library
    compile_ml_dsa();
}

fn compile_ml_dsa() {
    // Determine target and SDK path based on environment
    let target = std::env::var("TARGET").unwrap_or_default();

    // Ledger builds set TARGET to device name (stax, flex, nanosp, nanox)
    // Native builds set TARGET to architecture (aarch64-apple-darwin, etc.)
    let is_ledger_device = matches!(target.as_str(), "stax" | "flex" | "nanosp" | "nanox" | "nanosplus")
        || target.contains("thumb");

    if !is_ledger_device {
        println!("cargo:warning=Skipping ML-DSA C compilation for non-Ledger target: {}", target);
        return;
    }

    // Determine SDK path based on target
    let sdk_path = match target.as_str() {
        "stax" | "flex" => "/opt/stax-secure-sdk",
        "nanosp" | "nanosplus" | "nanox" => "/opt/nanos-secure-sdk",
        _ if target.contains("thumbv8") => "/opt/stax-secure-sdk",
        _ => "/opt/nanos-secure-sdk",
    };

    let c_dir = std::path::PathBuf::from("src/ml-dsa-c/m4fstack");

    // C source files to compile - MINIMAL set for keygen only
    // Excluded: smallpoly.c (only needed for signing)
    let c_files = [
        "fips202.c",
        "randombytes.c",
        "asm_fallbacks.c",  // Pure C implementations for NTT etc
        "packing.c",
        "poly.c",
        "polyvec.c",
        "rounding.c",
        "sign.c",
        // "smallpoly.c",  // Only needed for signing - contains small NTT
        "stack.c",         // Needed for keygen packing functions
        "symmetric-shake.c",
    ];

    let mut build = cc::Build::new();

    // Configure for ARM Cortex-M (Ledger devices)
    // Use clang as the compiler with ARM target
    build.compiler("clang");

    // Set the target for ARM Cortex-M33 (Stax/Flex) or M0+ (Nano)
    let arm_target = match target.as_str() {
        "stax" | "flex" => "thumbv8m.main-none-eabi",
        _ => "thumbv6m-none-eabi",
    };
    build.target(arm_target);

    // Add source files
    for file in &c_files {
        let path = c_dir.join(file);
        build.file(&path);
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Configure compiler
    build
        // Include paths
        .include(&c_dir)
        .include(format!("{}/include", sdk_path))
        .include(format!("{}/lib_cxng/include", sdk_path))
        // ARM newlib headers for string.h, stddef.h, etc.
        .include("/usr/lib/arm-none-eabi/include")

        // Dilithium mode 5 (ML-DSA-87)
        .define("DILITHIUM_MODE", "5")

        // ARM-specific flags
        .flag("-mcpu=cortex-m33")
        .flag("-mthumb")
        .flag("-fno-builtin")
        .flag("-fshort-enums")
        .flag("-fomit-frame-pointer")
        .flag("-fno-common")
        
        // Dead code elimination - each function/data in its own section
        .flag("-ffunction-sections")
        .flag("-fdata-sections")

        // Optimization for size
        .opt_level_str("z")

        // Warnings
        .warnings(false)

        // Output name
        .compile("ml_dsa");
    
    // Tell linker to garbage collect unused sections
    println!("cargo:rustc-link-arg=--gc-sections");

    println!("cargo:rustc-link-lib=static=ml_dsa");
}
