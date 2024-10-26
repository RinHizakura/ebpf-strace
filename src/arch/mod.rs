#[cfg(all(target_arch = "x86_64"))]
pub mod x86_64;
#[cfg(all(target_arch = "x86_64"))]
pub use crate::arch::x86_64::*;

#[cfg(all(target_arch = "aarch64"))]
pub mod aarch64;
#[cfg(all(target_arch = "aarch64"))]
pub use crate::arch::aarch64::*;
