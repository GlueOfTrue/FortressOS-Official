//! Single-core bounded kernel-broker IPC model, NOT production syscall ABI.
//! Grant issuance/revocation methods MUST be called only by trusted kernel code.
//! Incoming untrusted syscall registers must never invoke `issue` directly.
use crate::identity::{ProcessError, ProcessId, ProcessTable};

pub const MAX_MESSAGE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantHandle {
    slot: u16,
    generation: u64,
}
impl GrantHandle {
    pub const fn slot(self) -> u16 { self.slot }
    pub const fn generation(self) -> u64 { self.generation }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantRights(u8);
impl GrantRights {
    pub const NONE: Self = Self(0);
    pub const SEND: Self = Self(1);
    fn permits_send(self) -> bool { self.0 & 1 != 0 }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcError {
    Process(ProcessError),
    Full,
    Empty,
    MessageTooLarge,
    BadGrant,
    PermissionDenied,
    WrongRecipient,
    CapacityUnsupported,
}
impl From<ProcessError> for IpcError {
    fn from(error: ProcessError) -> Self { Self::Process(error) }
}

#[derive(Clone, Copy)]
enum GrantSlot {
    Free(u64),
    Live {
        generation: u64,
        from: ProcessId,
        to: ProcessId,
        rights: GrantRights,
    },
    Exhausted,
}

/// The trusted issuer checks process liveness and pins exact incarnations.
/// To enforce revocation, every delivery revalidates this table.
pub struct GrantTable<const N: usize> {
    slots: [GrantSlot; N],
}
impl<const N: usize> GrantTable<N> {
    pub const fn new() -> Self { Self { slots: [GrantSlot::Free(1); N] } }

    /// TRUSTED KERNEL API ONLY. Not callable as an untrusted syscall.
    pub fn issue<const P: usize>(
        &mut self, processes: &ProcessTable<P>, from: ProcessId,
        to: ProcessId, rights: GrantRights,
    ) -> Result<GrantHandle, IpcError> {
        processes.require_runnable(from)?;
        processes.require_runnable(to)?;
        if N > u16::MAX as usize { return Err(IpcError::CapacityUnsupported); }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if let GrantSlot::Free(generation) = *slot {
                *slot = GrantSlot::Live { generation, from, to, rights };
                return Ok(GrantHandle { slot: index as u16, generation });
            }
        }
        Err(IpcError::Full)
    }

    /// TRUSTED KERNEL API ONLY. Cannot claim hardware/IPC queue fence by itself.
    pub fn revoke(&mut self, handle: GrantHandle) -> Result<(), IpcError> {
        let slot = self.slots.get_mut(handle.slot as usize).ok_or(IpcError::BadGrant)?;
        match *slot {
            GrantSlot::Live { generation, .. } if generation == handle.generation => {
                *slot = match generation.checked_add(1) {
                    Some(next) => GrantSlot::Free(next),
                    None => GrantSlot::Exhausted,
                };
                Ok(())
            }
            _ => Err(IpcError::BadGrant),
        }
    }

    fn authorize_send(&self, handle: GrantHandle, from: ProcessId,
                      to: ProcessId) -> Result<(), IpcError> {
        match self.slots.get(handle.slot as usize) {
            Some(GrantSlot::Live { generation, from: owner, to: dest, rights })
                if *generation == handle.generation =>
            {
                if *owner != from || *dest != to {
                    return Err(IpcError::WrongRecipient);
                }
                if !rights.permits_send() {
                    return Err(IpcError::PermissionDenied);
                }
                Ok(())
            }
            _ => Err(IpcError::BadGrant),
        }
    }
}
impl<const N: usize> Default for GrantTable<N> {
    fn default() -> Self { Self::new() }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub from: ProcessId,
    pub to: ProcessId,
    grant: GrantHandle,
    len: u8,
    bytes: [u8; MAX_MESSAGE_BYTES],
}
impl Message {
    pub fn payload(&self) -> &[u8] { &self.bytes[..self.len as usize] }
}

/// Bounded FIFO: no allocation, no blocking, explicit Full/Empty.
/// All calls are serialized on ONE CPU until the scheduler supplies locking.
pub struct Mailbox<const N: usize> {
    owner: ProcessId,
    entries: [Option<Message>; N],
    head: usize,
    len: usize,
}
impl<const N: usize> Mailbox<N> {
    pub const fn new(owner: ProcessId) -> Self {
        Self { owner, entries: [None; N], head: 0, len: 0 }
    }
    pub const fn len(&self) -> usize { self.len }

    pub fn send<const P: usize, const G: usize>(
        &mut self, processes: &ProcessTable<P>, grants: &GrantTable<G>,
        sender: ProcessId, handle: GrantHandle, payload: &[u8],
    ) -> Result<(), IpcError> {
        processes.require_runnable(sender)?;
        processes.require_runnable(self.owner)?;
        grants.authorize_send(handle, sender, self.owner)?;
        if payload.len() > MAX_MESSAGE_BYTES { return Err(IpcError::MessageTooLarge); }
        if N == 0 { return Err(IpcError::Full); }
        if self.len == N { return Err(IpcError::Full); }
        let mut bytes = [0u8; MAX_MESSAGE_BYTES];
        bytes[..payload.len()].copy_from_slice(payload);
        let tail = (self.head + self.len) % N;
        self.entries[tail] = Some(Message {
            from: sender, to: self.owner, grant: handle,
            len: payload.len() as u8, bytes,
        });
        self.len += 1;
        Ok(())
    }

    /// Revalidate rights and BOTH process incarnations AT DELIVERY, not just
    /// enqueue. Revoked or stale queued messages are discarded in <= N steps.
    pub fn receive<const P: usize, const G: usize>(
        &mut self, processes: &ProcessTable<P>, grants: &GrantTable<G>,
        recipient: ProcessId,
    ) -> Result<Message, IpcError> {
        if recipient != self.owner { return Err(IpcError::WrongRecipient); }
        processes.require_runnable(recipient)?;
        while self.len > 0 {
            let msg = self.entries[self.head].take().ok_or(IpcError::BadGrant)?;
            self.head = (self.head + 1) % N; // N != 0 when len > 0
            self.len -= 1;
            if processes.require_runnable(msg.from).is_ok()
                && grants.authorize_send(msg.grant, msg.from, recipient).is_ok()
            {
                return Ok(msg);
            }
        }
        Err(IpcError::Empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AddressSpaceId, FaultReason};
    use std::vec;

    fn domains() -> (ProcessTable<3>, ProcessId, ProcessId, ProcessId) {
        let mut p = ProcessTable::<3>::new();
        let a = p.start(AddressSpaceId::new(0x1000, 1).unwrap()).unwrap();
        let b = p.start(AddressSpaceId::new(0x2000, 1).unwrap()).unwrap();
        let c = p.start(AddressSpaceId::new(0x3000, 1).unwrap()).unwrap();
        (p, a, b, c)
    }

    #[test]
    fn bounded_echo_authority_and_queue() {
        let (p, a, b, c) = domains();
        let mut g = GrantTable::<3>::new();
        let permit = g.issue(&p, a, b, GrantRights::SEND).unwrap();
        let deny = g.issue(&p, a, b, GrantRights::NONE).unwrap();
        let mut inbox = Mailbox::<1>::new(b);
        assert_eq!(inbox.send(&p, &g, c, permit, b"no"),
                   Err(IpcError::WrongRecipient));
        assert_eq!(inbox.send(&p, &g, a, deny, b"no"),
                   Err(IpcError::PermissionDenied));
        assert_eq!(inbox.send(&p, &g, a, permit, &vec![1u8; 65]),
                   Err(IpcError::MessageTooLarge));
        inbox.send(&p, &g, a, permit, b"echo").unwrap();
        assert_eq!(inbox.send(&p, &g, a, permit, b"overflow"),
                   Err(IpcError::Full));
        assert_eq!(inbox.receive(&p, &g, c), Err(IpcError::WrongRecipient));
        let msg = inbox.receive(&p, &g, b).unwrap();
        assert_eq!(msg.payload(), b"echo");
        assert_eq!(inbox.receive(&p, &g, b), Err(IpcError::Empty));
        let back = g.issue(&p, b, a, GrantRights::SEND).unwrap();
        let mut replies = Mailbox::<1>::new(a);
        replies.send(&p, &g, b, back, msg.payload()).unwrap();
        assert_eq!(replies.receive(&p, &g, a).unwrap().payload(), b"echo");
    }

    #[test]
    fn revocation_drops_already_queued_delivery() {
        let (p, a, b, _) = domains();
        let mut g = GrantTable::<1>::new();
        let old = g.issue(&p, a, b, GrantRights::SEND).unwrap();
        let mut inbox = Mailbox::<2>::new(b);
        inbox.send(&p, &g, a, old, b"secret").unwrap();
        g.revoke(old).unwrap();
        assert_eq!(inbox.receive(&p, &g, b), Err(IpcError::Empty));
        let new = g.issue(&p, a, b, GrantRights::SEND).unwrap();
        assert_ne!(old.generation(), new.generation());
        assert_eq!(inbox.send(&p, &g, a, old, b"stale"),
                   Err(IpcError::BadGrant));
        inbox.send(&p, &g, a, new, b"new").unwrap();
        assert_eq!(inbox.receive(&p, &g, b).unwrap().payload(), b"new");
    }
    #[test]
    fn terminated_sender_cannot_deliver_or_send() {
        let (mut p, a, b, _) = domains();
        let mut g = GrantTable::<1>::new();
        let token = g.issue(&p, a, b, GrantRights::SEND).unwrap();
        let mut inbox = Mailbox::<2>::new(b);
        inbox.send(&p, &g, a, token, b"stale").unwrap();
        p.fault(a, FaultReason::InvalidOpcode).unwrap();
        assert_eq!(inbox.receive(&p, &g, b), Err(IpcError::Empty));
        assert_eq!(inbox.send(&p, &g, a, token, b"no"),
                   Err(IpcError::Process(ProcessError::InvalidState)));
        assert!(p.require_runnable(b).is_ok());
    }
    #[test]
    fn zero_mailbox_and_grant_capacity_fail_closed() {
        let (p, a, b, _) = domains();
        let mut grants = GrantTable::<1>::new();
        let h = grants.issue(&p, a, b, GrantRights::SEND).unwrap();
        assert_eq!(grants.issue(&p, a, b, GrantRights::SEND), Err(IpcError::Full));
        let mut m = Mailbox::<0>::new(b);
        assert_eq!(m.send(&p, &grants, a, h, b"zero"), Err(IpcError::Full));
    }
}
