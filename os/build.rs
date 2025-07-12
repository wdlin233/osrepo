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
        ("loongarch64", "0x9000000080000000")
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

    // if target_arch == "riscv64" {
    //     println!("cargo:rerun-if-changed=../user/src/");
    //     println!("cargo:rerun-if-changed={}", TARGET_PATH);
    // } else if target_arch == "loongarch64" {
    //     let outdir = env::var("OUT_DIR").unwrap();
    //     let link_script = Path::new(&outdir).join("link.lds");
    //     let mut script = File::create(&link_script).unwrap();
    //     script.write_all(include_bytes!("src/linker_la.ld")).unwrap();
    //     println!("cargo:rustc-link-arg=-T{}", &link_script.display());
    //     //println!("cargo:rustc-link-arg=-nostdlib"); //关闭gcc的默认链接
    //                                             // println!("cargo:rustc-link-arg=-no-pie"); //rust默认连接到Scrt1.o，使用动态链接
    //                                             // println!("cargo:rustc-link-arg=-Wl,-Map=rust.map");
    //     println!("cargo:rerun-if-change=src/linker_la.ld");
    // } else {
    //     panic!("Unsupported architecture: {}", target_arch);
    // }
}