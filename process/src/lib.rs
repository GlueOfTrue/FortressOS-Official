//! FortressOS PROCESS 08 — bounded, no-allocator process contract.
//!
//! This crate is usable by a `no_std` kernel but is NOT an execution engine:
//! callers must implement and independently verify page tables, CR3 switches,
//! CPL3 entry/return, trap provenance and shootdown before claiming K3 isolation.
//! In particular, host-provided cleanup witnesses are NOT hardware proofs.
#![no_std]
#![forbid(unsafe_code)]

pub mod elf;
pub mod identity;
pub mod ipc;

#[cfg(test)]
extern crate std;
