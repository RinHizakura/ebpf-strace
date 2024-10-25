#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub mod x86_64;
pub use crate::arch::x86_64::*;
