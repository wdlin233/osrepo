//! Represents system information similar to the Unix `uname` command.
//!
//! This struct contains information about the operating system, including its name, version, and hardware architecture.
//! It is designed to mimic the data structure used by the `uname` system call in Unix-like systems.
//!
//! # Fields
//! - `sysname`: The name of the operating system.
//! - `nodename`: The name of the machine on the network, typically the hostname.
//! - `release`: The release version of the operating system.
//! - `version`: The version information of the operating system.
//! - `machine`: The hardware architecture of the machine.
//! - `domainname`: The network domain name of the machine.
//!



/// to save system name
#[repr(C)]
#[derive(Debug,Clone)]
pub struct UTSname{
    /// 操作系统名称，固定
    pub sysname: [u8;65],
    /// 网络节点名称，通常是主机名称，一般由用户定义
    pub nodename: [u8;65],
    /// 操作系统版本号
    pub release: [u8;65],
    /// 操作系统版本信息
    pub version: [u8;65],
    /// 硬件架构
    pub machine: [u8;65],
    /// 网络域名
    pub domainname: [u8;65],
}

impl UTSname {
    /// UtSname
    pub fn new()->Self {
        UTSname {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        }
    }
    /// get 
    pub fn get(&mut self){
        let sn = "Substium";
        let nn = "rcos";
        let re = "0.1.0";
        let v = "0.1.0-dev (2025.06.30) risc-v";
        let ma = "RISC-V";
        let dn = "";
        change_to_c(&mut self.sysname,sn.as_bytes());
        change_to_c(&mut self.nodename,nn.as_bytes());
        change_to_c(&mut self.release,re.as_bytes());
        change_to_c(&mut self.version,v.as_bytes());
        change_to_c(&mut self.machine,ma.as_bytes());
        change_to_c(&mut self.domainname,dn.as_bytes());
    }

}

/// change 
pub fn change_to_c(source: &mut [u8;65],ch: &[u8]){
    let size = ch.len();
    if size > 64 {
        debug!("can not change to c");
    }
    else {
        debug!("change to c ing...");
        for i in 0..size {
            source[i] = ch[i];
        }
        for i in size..65 {
            source[i] = 0;
        }
    }
}

