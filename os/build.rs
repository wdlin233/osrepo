static TARGET_PATH: &str = "../user/target/riscv64gc-unknown-none-elf/release/"; // riscv64gc-unknown-none-elf

use std::{env, fs::File, include_bytes, io::Write, path::Path};

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch == "riscv64" {
        println!("cargo:rerun-if-changed=../user/src/");
        println!("cargo:rerun-if-changed={}", TARGET_PATH);
    } else if target_arch == "loongarch64" {
        let outdir = env::var("OUT_DIR").unwrap();
        let link_script = Path::new(&outdir).join("link.lds");
        let mut script = File::create(&link_script).unwrap();
        script.write_all(include_bytes!("src/linker_la.ld")).unwrap();
        println!("cargo:rustc-link-arg=-T{}", &link_script.display());
        //println!("cargo:rustc-link-arg=-nostdlib"); //关闭gcc的默认链接
                                                // println!("cargo:rustc-link-arg=-no-pie"); //rust默认连接到Scrt1.o，使用动态链接
                                                // println!("cargo:rustc-link-arg=-Wl,-Map=rust.map");
        println!("cargo:rerun-if-change=src/linker_la.ld");
    } else {
        panic!("Unsupported architecture: {}", target_arch);
    }
}