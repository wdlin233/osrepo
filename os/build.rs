use std::{env, io::Result};

fn main() -> Result<()> {
    gen_linker_script()
}

fn gen_linker_script() -> Result<()> {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("can't find target");
    let fname = format!("linker_{}.lds", target_arch);
    let (output_arch, kernel_base) = if target_arch.contains("riscv64") {
        ("riscv", "0x80200000") // OpenSBI
    } else if target_arch.contains("loongarch64") {
        ("loongarch64", "0x9000000000200000")
    } else {
        (target_arch.as_str(), "0")
    };
    let ld_content = std::fs::read_to_string("linker.lds")?;
    let ld_content = ld_content.replace("%ARCH%", output_arch);
    let ld_content = ld_content.replace("%KERNEL_BASE%", kernel_base);

    std::fs::write(&fname, ld_content)?;
    println!("cargo:rustc-link-arg=-T{}", fname);
    println!("cargo:rerun-if-env-changed=CARGO_CFG_KERNEL_BASE");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=linker.lds");
    Ok(())
}