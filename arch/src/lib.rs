#![no_std]
#![forbid(unsafe_code)]

//! Host-model-only x86-64 IRQ lease/dispatch state machine.
//! No IDT, APIC, EOI, CPU entry assembly, PCI or DMA implementation exists here.
//! A real interrupt handler needs an independently reviewed concurrency and
//! controller contract before calling any part of this code on target hardware.

/// Device MSI/MSI-X vectors in draft A11. Not a hardware allocation claim.
/// 0..31 exceptions, 32..63 bootstrap/legacy, 224..255 system/APIC/IPI.
pub const FIRST_DEVICE_VECTOR: u8 = 0x40;
pub const LAST_DEVICE_VECTOR: u8 = 0xdf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceKey {
    pub id: u64,
    /// Must change on unplug/replug, reset, or identity recycling.
    pub incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrqLease {
    pub vector: u8,
    pub generation: u64,
    pub device: DeviceKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryTicket {
    pub lease: IrqLease,
    /// Prevents a delayed completion from acknowledging a newer delivery
    /// under the same lease.
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Free,
    Masked,
    Ready,
    Handling,
    HandlingMasked,
    Completed,
    CompletedMasked,
    RetiringHandling,
    RetiringCompleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retire {
    Immediate,
    DeferredUntilAck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqError {
    ReservedVector,
    InvalidDevice,
    AlreadyRegistered,
    Unregistered,
    StaleLease,
    Masked,
    Busy,
    Retiring,
    InvalidOrder,
    GenerationExhausted,
    SequenceExhausted,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    sequence: u64,
    device: Option<DeviceKey>,
    phase: Phase,
}

const EMPTY_SLOT: Slot = Slot {
    generation: 0,
    sequence: 0,
    device: None,
    phase: Phase::Free,
};

/// Deterministic single-threaded transition system only.
/// The caller must serialize all operations; this is NOT SMP-safe.
pub struct IrqTable {
    slots: [Slot; 256],
}

impl Default for IrqTable {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqTable {
    pub const fn new() -> Self {
        Self { slots: [EMPTY_SLOT; 256] }
    }

    fn checked_vector(vector: u8) -> Result<usize, IrqError> {
        if vector < FIRST_DEVICE_VECTOR || vector > LAST_DEVICE_VECTOR {
            return Err(IrqError::ReservedVector);
        }
        Ok(vector as usize)
    }

    fn slot_for_lease(&mut self, lease: IrqLease) -> Result<&mut Slot, IrqError> {
        let index = Self::checked_vector(lease.vector)?;
        let slot = &mut self.slots[index];
        if slot.phase == Phase::Free {
            return Err(IrqError::Unregistered);
        }
        if slot.generation != lease.generation || slot.device != Some(lease.device) {
            return Err(IrqError::StaleLease);
        }
        Ok(slot)
    }

    fn slot_for_ticket(&mut self, ticket: DeliveryTicket) -> Result<&mut Slot, IrqError> {
        let slot = self.slot_for_lease(ticket.lease)?;
        if slot.sequence != ticket.sequence || ticket.sequence == 0 {
            return Err(IrqError::StaleLease);
        }
        Ok(slot)
    }

    pub fn register(&mut self, vector: u8, device: DeviceKey) -> Result<IrqLease, IrqError> {
        let index = Self::checked_vector(vector)?;
        if device.id == 0 || device.incarnation == 0 {
            return Err(IrqError::InvalidDevice);
        }
        let slot = &mut self.slots[index];
        if slot.phase != Phase::Free {
            return Err(IrqError::AlreadyRegistered);
        }
        let next = slot.generation.checked_add(1).ok_or(IrqError::GenerationExhausted)?;
        slot.generation = next;
        slot.sequence = 0;
        slot.device = Some(device);
        slot.phase = Phase::Masked; // fail closed until the controller is ready
        Ok(IrqLease { vector, generation: next, device })
    }

    pub fn phase(&self, vector: u8) -> Result<Phase, IrqError> {
        let index = Self::checked_vector(vector)?;
        Ok(self.slots[index].phase)
    }

    pub fn mask(&mut self, lease: IrqLease) -> Result<(), IrqError> {
        let slot = self.slot_for_lease(lease)?;
        slot.phase = match slot.phase {
            Phase::Masked => Phase::Masked,
            Phase::Ready => Phase::Masked,
            Phase::Handling => Phase::HandlingMasked,
            Phase::HandlingMasked => Phase::HandlingMasked,
            Phase::Completed => Phase::CompletedMasked,
            Phase::CompletedMasked => Phase::CompletedMasked,
            Phase::RetiringHandling | Phase::RetiringCompleted => return Err(IrqError::Retiring),
            Phase::Free => return Err(IrqError::Unregistered),
        };
        Ok(())
    }

    pub fn unmask(&mut self, lease: IrqLease) -> Result<(), IrqError> {
        let slot = self.slot_for_lease(lease)?;
        match slot.phase {
            Phase::Masked | Phase::Ready => {
                slot.phase = Phase::Ready;
                Ok(())
            }
            Phase::RetiringHandling | Phase::RetiringCompleted => Err(IrqError::Retiring),
            _ => Err(IrqError::Busy),
        }
    }

    /// Models delivery AFTER hardware routing and device identity verification.
    /// No device register read or CPU handler invocation takes place.
    pub fn deliver(&mut self, lease: IrqLease) -> Result<DeliveryTicket, IrqError> {
        let slot = self.slot_for_lease(lease)?;
        match slot.phase {
            Phase::Ready => {
                let next = slot.sequence.checked_add(1).ok_or(IrqError::SequenceExhausted)?;
                slot.sequence = next;
                slot.phase = Phase::Handling;
                Ok(DeliveryTicket { lease, sequence: next })
            }
            Phase::Masked => Err(IrqError::Masked),
            Phase::RetiringHandling | Phase::RetiringCompleted => Err(IrqError::Retiring),
            _ => Err(IrqError::Busy),
        }
    }

    /// Handler has finished its work. NOT an APIC EOI.
    pub fn finish_handler(&mut self, ticket: DeliveryTicket) -> Result<(), IrqError> {
        let slot = self.slot_for_ticket(ticket)?;
        slot.phase = match slot.phase {
            Phase::Handling => Phase::Completed,
            Phase::HandlingMasked => Phase::CompletedMasked,
            Phase::RetiringHandling => Phase::RetiringCompleted,
            _ => return Err(IrqError::InvalidOrder),
        };
        Ok(())
    }

    /// Models verified controller acknowledgment after handler completion.
    /// This does NOT write APIC EOI or prove that a real device is quiesced.
    pub fn acknowledge(&mut self, ticket: DeliveryTicket) -> Result<(), IrqError> {
        let slot = self.slot_for_ticket(ticket)?;
        match slot.phase {
            Phase::Completed => slot.phase = Phase::Ready,
            Phase::CompletedMasked => slot.phase = Phase::Masked,
            Phase::RetiringCompleted => {
                slot.phase = Phase::Free;
                slot.device = None;
            }
            _ => return Err(IrqError::InvalidOrder),
        }
        Ok(())
    }

    /// Logical retirement masks future dispatch immediately. The physical
    /// controller/PCI route must be masked *before* retirement in an actual driver.
    pub fn unregister(&mut self, lease: IrqLease) -> Result<Retire, IrqError> {
        let slot = self.slot_for_lease(lease)?;
        match slot.phase {
            Phase::Masked | Phase::Ready => {
                slot.phase = Phase::Free;
                slot.device = None;
                Ok(Retire::Immediate)
            }
            Phase::Handling | Phase::HandlingMasked => {
                slot.phase = Phase::RetiringHandling;
                Ok(Retire::DeferredUntilAck)
            }
            Phase::Completed | Phase::CompletedMasked => {
                slot.phase = Phase::RetiringCompleted;
                Ok(Retire::DeferredUntilAck)
            }
            Phase::RetiringHandling | Phase::RetiringCompleted => Err(IrqError::Retiring),
            Phase::Free => Err(IrqError::Unregistered),
        }
    }
}

/// These are *planned* handler flags, not observed CPU flags.
/// A02 must review CPL/CS, stack, IST, GS/FS, SMAP, CET, and interrupt gates.
pub const RFLAGS_IF: u64 = 1 << 9;
pub const RFLAGS_DF: u64 = 1 << 10;
pub const RFLAGS_NT: u64 = 1 << 14;
pub const RFLAGS_AC: u64 = 1 << 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryError {
    UnsupportedNestedTask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuEntryPlan {
    pub saved_rflags: u64,
    /// Intended flags after a reviewed entry stub; no assembly implemented.
    pub handler_rflags: u64,
}

impl CpuEntryPlan {
    pub fn for_saved_flags(saved_rflags: u64) -> Result<Self, EntryError> {
        if saved_rflags & RFLAGS_NT != 0 {
            return Err(EntryError::UnsupportedNestedTask);
        }
        Ok(Self {
            saved_rflags,
            // A real entry stub must ensure these conditions before Rust.
            handler_rflags: saved_rflags & !(RFLAGS_DF | RFLAGS_IF | RFLAGS_AC),
        })
    }

    pub fn planned_exit_flags(self) -> u64 {
        // Logical IRETQ destination only. Does NOT execute IRETQ or alter RFLAGS.
        self.saved_rflags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GPU: DeviceKey = DeviceKey { id: 10, incarnation: 1 };
    const USB: DeviceKey = DeviceKey { id: 12, incarnation: 1 };

    #[test]
    fn valid_dispatch_finish_ack_then_reuse_rejects_stale() {
        let mut t = IrqTable::new();
        let lease = t.register(0x40, GPU).unwrap();
        assert_eq!(t.phase(0x40), Ok(Phase::Masked));
        t.unmask(lease).unwrap();
        let first = t.deliver(lease).unwrap();
        assert_eq!(first.sequence, 1);
        t.finish_handler(first).unwrap();
        t.acknowledge(first).unwrap();
        assert_eq!(t.phase(0x40), Ok(Phase::Ready));
        assert_eq!(t.unregister(lease), Ok(Retire::Immediate));
        let newer = t.register(0x40, USB).unwrap();
        assert_eq!(newer.generation, lease.generation + 1);
        assert_eq!(t.unmask(lease), Err(IrqError::StaleLease));
        t.unmask(newer).unwrap();
        let latest = t.deliver(newer).unwrap();
        assert_eq!(t.acknowledge(first), Err(IrqError::StaleLease));
        t.finish_handler(latest).unwrap();
        t.acknowledge(latest).unwrap();
    }

    #[test]
    fn rejects_reserved_and_duplicate_vectors_and_invalid_device() {
        let mut t = IrqTable::new();
        assert_eq!(t.register(31, GPU), Err(IrqError::ReservedVector));
        assert_eq!(t.register(0xff, GPU), Err(IrqError::ReservedVector));
        assert_eq!(t.register(0x40, DeviceKey { id: 0, incarnation: 1 }), Err(IrqError::InvalidDevice));
        let _ = t.register(0x40, GPU).unwrap();
        assert_eq!(t.register(0x40, USB), Err(IrqError::AlreadyRegistered));
    }

    #[test]
    fn delivery_masking_and_no_premature_ack() {
        let mut t = IrqTable::new();
        let lease = t.register(0x41, GPU).unwrap();
        assert_eq!(t.deliver(lease), Err(IrqError::Masked));
        t.unmask(lease).unwrap();
        let ticket = t.deliver(lease).unwrap();
        assert_eq!(t.deliver(lease), Err(IrqError::Busy));
        assert_eq!(t.acknowledge(ticket), Err(IrqError::InvalidOrder));
        t.mask(lease).unwrap();
        t.finish_handler(ticket).unwrap();
        assert_eq!(t.phase(0x41), Ok(Phase::CompletedMasked));
        assert_eq!(t.unmask(lease), Err(IrqError::Busy));
        t.acknowledge(ticket).unwrap();
        assert_eq!(t.phase(0x41), Ok(Phase::Masked));
        assert_eq!(t.acknowledge(ticket), Err(IrqError::InvalidOrder));
    }

    #[test]
    fn retiring_during_handler_defers_vector_reuse_until_ack() {
        let mut t = IrqTable::new();
        let lease = t.register(0x42, USB).unwrap();
        t.unmask(lease).unwrap();
        let ticket = t.deliver(lease).unwrap();
        assert_eq!(t.unregister(lease), Ok(Retire::DeferredUntilAck));
        assert_eq!(t.register(0x42, GPU), Err(IrqError::AlreadyRegistered));
        assert_eq!(t.deliver(lease), Err(IrqError::Retiring));
        t.finish_handler(ticket).unwrap();
        assert_eq!(t.phase(0x42), Ok(Phase::RetiringCompleted));
        assert_eq!(t.unregister(lease), Err(IrqError::Retiring));
        t.acknowledge(ticket).unwrap();
        assert_eq!(t.phase(0x42), Ok(Phase::Free));
        let new_lease = t.register(0x42, GPU).unwrap();
        assert_ne!(new_lease.generation, lease.generation);
    }

    #[test]
    fn wrong_ticket_generation_or_sequence_fails_closed() {
        let mut t = IrqTable::new();
        let lease = t.register(0x43, GPU).unwrap();
        t.unmask(lease).unwrap();
        let ticket = t.deliver(lease).unwrap();
        let forged = DeliveryTicket { sequence: ticket.sequence + 1, ..ticket };
        assert_eq!(t.finish_handler(forged), Err(IrqError::StaleLease));
        let foreign = DeliveryTicket { lease: IrqLease { device: USB, ..lease }, ..ticket };
        assert_eq!(t.acknowledge(foreign), Err(IrqError::StaleLease));
        t.finish_handler(ticket).unwrap();
        t.acknowledge(ticket).unwrap();
        let next = t.deliver(lease).unwrap();
        assert_eq!(t.finish_handler(ticket), Err(IrqError::StaleLease));
        t.finish_handler(next).unwrap();
        t.acknowledge(next).unwrap();
    }

    #[test]
    fn exhausted_generation_and_delivery_sequence_never_wrap() {
        let mut t = IrqTable::new();
        t.slots[0x44].generation = u64::MAX;
        assert_eq!(t.register(0x44, GPU), Err(IrqError::GenerationExhausted));
        let lease = t.register(0x45, USB).unwrap();
        t.unmask(lease).unwrap();
        t.slots[0x45].sequence = u64::MAX;
        assert_eq!(t.deliver(lease), Err(IrqError::SequenceExhausted));
        assert_eq!(t.phase(0x45), Ok(Phase::Ready));
    }

    #[test]
    fn entry_plan_clears_unsafe_handler_flags_and_preserves_saved_flags() {
        let input = RFLAGS_IF | RFLAGS_DF | RFLAGS_AC | 0x2;
        let plan = CpuEntryPlan::for_saved_flags(input).unwrap();
        assert_eq!(plan.handler_rflags & (RFLAGS_IF | RFLAGS_DF | RFLAGS_AC), 0);
        assert_eq!(plan.planned_exit_flags(), input);
        assert_eq!(CpuEntryPlan::for_saved_flags(input | RFLAGS_NT), Err(EntryError::UnsupportedNestedTask));
    }
}
