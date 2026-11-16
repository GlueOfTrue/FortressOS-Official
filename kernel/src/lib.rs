#![no_std]

pub mod bootinfo;

#[cfg(any(test, feature = "g1-fixture-console"))]
pub mod console;
