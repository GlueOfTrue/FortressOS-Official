//! Process incarnation and address-space ownership; pure, bounded state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessId {
    slot: u16,
    generation: u64,
}
impl ProcessId {
    pub const fn slot(self) -> u16 { self.slot }
    pub const fn generation(self) -> u64 { self.generation }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpaceId {
    root_frame: u64,
    generation: u64,
}
impl AddressSpaceId {
    /// The root is a PHYSICAL, allocated and owned PML4 frame (not a grant).
    /// The real VMM must attest ownership and nonaliasing before calling.
    pub const fn new(root_frame: u64, generation: u64) -> Result<Self, ProcessError> {
        if root_frame == 0 || root_frame & 0xfff != 0 || generation == 0 {
            return Err(ProcessError::InvalidSpace);
        }
        Ok(Self { root_frame, generation })
    }
    pub const fn root_frame(self) -> u64 { self.root_frame }
    pub const fn generation(self) -> u64 { self.generation }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultReason {
    PageFault,
    InvalidOpcode,
    GeneralProtection,
    DivideError,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Exited,
    Faulted(FaultReason),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessView {
    pub address_space: AddressSpaceId,
    pub state: ProcessState,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessError {
    InvalidSpace,
    DuplicateAddressSpace,
    Full,
    StaleProcess,
    InvalidState,
    CleanupIncomplete,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Free(u64),
    Live {
        generation: u64,
        address_space: AddressSpaceId,
        state: ProcessState,
    },
    Exhausted,
}

/// These are *claims by trusted ARCH/MEM/CAP code*, not user-supplied flags.
/// Proof of CPU/TLB quiescence requires actual VMM/ARCH synchronization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetirementWitness {
    pub threads_quiesced: bool,
    pub cpu_translation_invalidated: bool,
    pub grants_revoked: bool,
}
impl RetirementWitness {
    const fn complete(self) -> bool {
        self.threads_quiesced && self.cpu_translation_invalidated && self.grants_revoked
    }
}

/// Slot+generation prevents ABA for identities until u64 exhaustion.
/// This is single-CPU/sequential; SMP needs locks/atomics and release barriers.
pub struct ProcessTable<const N: usize> {
    slots: [Slot; N],
}
impl<const N: usize> ProcessTable<N> {
    pub const fn new() -> Self { Self { slots: [Slot::Free(1); N] } }

    pub fn start(&mut self, address_space: AddressSpaceId) -> Result<ProcessId, ProcessError> {
        // Distinct live domains MUST NOT share the same page-table root even
        // when the VMM incarnation differs. Root reuse requires retire barrier.
        if self.slots.iter().any(|s| matches!(
            s, Slot::Live { address_space: a, .. } if a.root_frame == address_space.root_frame
        )) {
            return Err(ProcessError::DuplicateAddressSpace);
        }
        if N > u16::MAX as usize {
            return Err(ProcessError::Full);
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if let Slot::Free(generation) = *slot {
                *slot = Slot::Live {
                    generation,
                    address_space,
                    state: ProcessState::Runnable,
                };
                return Ok(ProcessId { slot: index as u16, generation });
            }
        }
        Err(ProcessError::Full)
    }

    pub fn get(&self, pid: ProcessId) -> Result<ProcessView, ProcessError> {
        match self.slots.get(pid.slot as usize) {
            Some(Slot::Live { generation, address_space, state })
                if *generation == pid.generation =>
            {
                Ok(ProcessView { address_space: *address_space, state: *state })
            }
            _ => Err(ProcessError::StaleProcess),
        }
    }

    pub fn require_runnable(&self, pid: ProcessId) -> Result<ProcessView, ProcessError> {
        let view = self.get(pid)?;
        if view.state != ProcessState::Runnable {
            return Err(ProcessError::InvalidState);
        }
        Ok(view)
    }

    fn live_slot_mut(&mut self, pid: ProcessId) -> Result<&mut Slot, ProcessError> {
        let slot = self.slots.get_mut(pid.slot as usize).ok_or(ProcessError::StaleProcess)?;
        if !matches!(slot, Slot::Live { generation, .. } if *generation == pid.generation) {
            return Err(ProcessError::StaleProcess);
        }
        Ok(slot)
    }

    pub fn fault(&mut self, pid: ProcessId, reason: FaultReason) -> Result<(), ProcessError> {
        match self.live_slot_mut(pid)? {
            Slot::Live { state: s @ ProcessState::Runnable, .. } => {
                *s = ProcessState::Faulted(reason);
                Ok(())
            }
            _ => Err(ProcessError::InvalidState),
        }
    }

    pub fn exit(&mut self, pid: ProcessId) -> Result<(), ProcessError> {
        match self.live_slot_mut(pid)? {
            Slot::Live { state: s @ ProcessState::Runnable, .. } => {
                *s = ProcessState::Exited;
                Ok(())
            }
            _ => Err(ProcessError::InvalidState),
        }
    }

    pub fn reap(&mut self, pid: ProcessId, witness: RetirementWitness)
        -> Result<(), ProcessError>
    {
        // No state mutation if a witness is incomplete or the process runs.
        if !witness.complete() { return Err(ProcessError::CleanupIncomplete); }
        let slot = self.live_slot_mut(pid)?;
        match *slot {
            Slot::Live { state: ProcessState::Runnable, .. } =>
                Err(ProcessError::InvalidState),
            Slot::Live { generation, .. } => {
                *slot = match generation.checked_add(1) {
                    Some(next) => Slot::Free(next),
                    None => Slot::Exhausted, // fail closed on wraparound
                };
                Ok(())
            }
            _ => Err(ProcessError::StaleProcess),
        }
    }
}
impl<const N: usize> Default for ProcessTable<N> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn space(frame: u64) -> AddressSpaceId {
        AddressSpaceId::new(frame, 1).unwrap()
    }
    fn witness() -> RetirementWitness {
        RetirementWitness { threads_quiesced: true,
            cpu_translation_invalidated: true, grants_revoked: true }
    }
    #[test]
    fn two_distinct_domains_fault_only_one() {
        let mut p = ProcessTable::<2>::new();
        let a = p.start(space(0x1000)).unwrap();
        let b = p.start(space(0x2000)).unwrap();
        assert_ne!(p.get(a).unwrap().address_space.root_frame(),
                   p.get(b).unwrap().address_space.root_frame());
        p.fault(a, FaultReason::PageFault).unwrap();
        assert_eq!(p.require_runnable(a), Err(ProcessError::InvalidState));
        assert!(p.require_runnable(b).is_ok());
        assert_eq!(p.start(space(0x3000)), Err(ProcessError::Full));
        assert_eq!(p.reap(a, RetirementWitness::default()),
                   Err(ProcessError::CleanupIncomplete));
        p.reap(a, witness()).unwrap();
        let c = p.start(space(0x3000)).unwrap();
        assert_eq!(a.slot(), c.slot());
        assert_ne!(a.generation(), c.generation());
        assert_eq!(p.get(a), Err(ProcessError::StaleProcess));
        assert!(p.require_runnable(b).is_ok());
    }
    #[test]
    fn alias_and_bad_spaces_denied() {
        assert!(AddressSpaceId::new(1, 1).is_err());
        assert!(AddressSpaceId::new(0x1000, 0).is_err());
        let mut p = ProcessTable::<2>::new();
        let a = p.start(space(0x1000)).unwrap();
        assert_eq!(p.start(AddressSpaceId::new(0x1000, 99).unwrap()),
                   Err(ProcessError::DuplicateAddressSpace));
        assert_eq!(p.reap(a, witness()), Err(ProcessError::InvalidState));
        p.exit(a).unwrap();
        p.reap(a, witness()).unwrap();
        assert!(p.start(space(0x1000)).is_ok());
    }
}
