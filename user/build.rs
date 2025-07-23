use std::io::Result;

fn main() -> Result<()>{
    gen_linker_script()
}

fn gen_linker_script() -> Result<()> {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("can't find target");
    let fname = format!("linker_{}.lds", arch);
    let output_arch= if arch.contains("riscv64") {
        "riscv"
    } else if arch.contains("loongarch64") {
        "loongarch64"
    } else {
        arch.as_str()
    };
    let ld_content = std::fs::read_to_string("linker.lds")?;
    let ld_content = ld_content.replace("%ARCH%", output_arch);
    
    std::fs::write(&fname, ld_content)?;
    println!("cargo:rustc-link-arg=-T{}", fname);
    println!("cargo:rerun-if-env-changed=CARGO_CFG_KERNEL_BASE");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=linker.lds");

    Ok(())
}
