#![no_std]
#![forbid(unsafe_code)]
//! Host-testable, fixed-capacity reference semantics. Not a syscall ABI or kernel proof.
//! The kernel MUST authenticate DomainId and serialize all mutations, including policy changes.

pub mod ipc;

use core::ops::{BitAnd, BitOr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidDomain,
    InvalidObject,
    InvalidHandle,
    InsufficientRights,
    Amplification,
    Full,
    Exhausted,
    PolicyDenied,
    NotEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DomainId {
    slot: u32,
    incarnation: u64,
}

impl DomainId {
    /// This is a kernel identity, never an identity claim accepted from userspace.
    pub const fn new(slot: u32, incarnation: u64) -> Option<Self> {
        if incarnation == 0 { None } else { Some(Self { slot, incarnation }) }
    }
    pub const fn slot(self) -> u32 { self.slot }
    pub const fn incarnation(self) -> u64 { self.incarnation }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u16);
impl Rights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const SEND: Self = Self(1 << 2);
    pub const RECEIVE: Self = Self(1 << 3);
    pub const REPLY: Self = Self(1 << 4);
    pub const TRANSFER: Self = Self(1 << 5);
    pub const ADMIN: Self = Self(1 << 6);
    pub const VALID_BITS: u16 = (1 << 7) - 1;
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::VALID_BITS == 0 { Some(Self(bits)) } else { None }
    }
    pub const fn bits(self) -> u16 { self.0 }
    pub const fn contains(self, other: Self) -> bool { self.0 & other.0 == other.0 }
    pub const fn subset_of(self, other: Self) -> bool { other.contains(self) }
}
impl BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}
impl BitAnd for Rights {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId {
    slot: usize,
    incarnation: u64,
}
impl ObjectId {
    pub const fn slot(self) -> usize { self.slot }
    pub const fn incarnation(self) -> u64 { self.incarnation }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind { Generic, Endpoint }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapHandle {
    slot: usize,
    generation: u64,
    domain: DomainId,
}
impl CapHandle {
    pub const fn slot(self) -> usize { self.slot }
    pub const fn generation(self) -> u64 { self.generation }
    pub const fn domain(self) -> DomainId { self.domain }
}

/// Canonical provenance is minted and stored in a protected object slot, never
/// supplied by a derive/transfer caller. Copies are informational, not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProvenance {
    object: ObjectId,
    founder: DomainId,
    original_rights: Rights,
}
impl RootProvenance {
    pub const fn object(self) -> ObjectId { self.object }
    pub const fn founder(self) -> DomainId { self.founder }
    pub const fn original_rights(self) -> Rights { self.original_rights }
}

#[derive(Clone, Copy, Debug)]
struct ObjectRecord {
    provenance: RootProvenance,
    kind: ObjectKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapKey { slot: usize, generation: u64 }
#[derive(Clone, Copy, Debug)]
struct CapRecord {
    object: ObjectId,
    owner: DomainId,
    root: RootProvenance,
    grant: Rights,
    bound: Rights,
    parent: Option<CapKey>,
}
#[derive(Clone, Copy, Debug)]
struct Slot<T: Copy> {
    generation: u64,
    value: Option<T>,
}
impl<T: Copy> Slot<T> {
    fn vacant() -> Self { Self { generation: 1, value: None } }
    fn reusable(&self) -> bool { self.value.is_none() && self.generation != u64::MAX }
    fn retire(&mut self) {
        self.value = None;
        // A saturated generation is permanently retired; no handle/object ABA.
        self.generation = self.generation.checked_add(1).unwrap_or(u64::MAX);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CapView {
    pub object: ObjectId,
    pub kind: ObjectKind,
    pub owner: DomainId,
    pub root: RootProvenance,
    pub grant: Rights,
    pub bound: Rights,
}
impl CapView {
    pub fn effective(self) -> Rights { self.grant & self.bound }
}

pub trait TransferPolicy {
    fn permit(&self, from: DomainId, to: DomainId, object: ObjectId, rights: Rights) -> bool;
}

/// Opaque preparation. A snapshot is never sufficient authority for commit.
#[derive(Clone, Copy, Debug)]
pub struct PreparedTransfer {
    source: CapHandle,
    destination: DomainId,
    object: ObjectId,
    requested_grant: Rights,
    requested_bound: Rights,
}

pub struct CapTable<const OBJECTS: usize, const HANDLES: usize> {
    objects: [Slot<ObjectRecord>; OBJECTS],
    handles: [Slot<CapRecord>; HANDLES],
}

impl<const O: usize, const H: usize> Default for CapTable<O, H> {
    fn default() -> Self { Self::new() }
}

impl<const O: usize, const H: usize> CapTable<O, H> {
    pub fn new() -> Self {
        Self {
            objects: core::array::from_fn(|_| Slot::vacant()),
            handles: core::array::from_fn(|_| Slot::vacant()),
        }
    }

    /// PRIVILEGED KERNEL BOOTSTRAP ONLY. Calls must not be reachable from a
    /// userspace syscall accepting a caller-supplied rights mask/domain.
    pub fn bootstrap(
        &mut self, founder: DomainId, kind: ObjectKind, rights: Rights,
    ) -> Result<(ObjectId, CapHandle), Error> {
        let oi = self.objects.iter().position(Slot::reusable).ok_or(Error::Full)?;
        let hi = self.handles.iter().position(Slot::reusable).ok_or(Error::Full)?;
        let id = ObjectId { slot: oi, incarnation: self.objects[oi].generation };
        let root = RootProvenance { object: id, founder, original_rights: rights };
        self.objects[oi].value = Some(ObjectRecord { provenance: root, kind });
        let handle = CapHandle {
            slot: hi, generation: self.handles[hi].generation, domain: founder,
        };
        self.handles[hi].value = Some(CapRecord {
            object: id, owner: founder, root, grant: rights, bound: rights, parent: None,
        });
        Ok((id, handle))
    }

    fn object(&self, id: ObjectId) -> Result<ObjectRecord, Error> {
        let slot = self.objects.get(id.slot).ok_or(Error::InvalidObject)?;
        if slot.generation != id.incarnation { return Err(Error::InvalidObject); }
        slot.value.ok_or(Error::InvalidObject)
    }

    fn resolve(&self, caller: DomainId, handle: CapHandle) -> Result<CapRecord, Error> {
        if handle.domain != caller { return Err(Error::InvalidHandle); }
        let slot = self.handles.get(handle.slot).ok_or(Error::InvalidHandle)?;
        if slot.generation != handle.generation { return Err(Error::InvalidHandle); }
        let cap = slot.value.ok_or(Error::InvalidHandle)?;
        if cap.owner != caller { return Err(Error::InvalidHandle); }
        let obj = self.object(cap.object).map_err(|_| Error::InvalidHandle)?;
        if cap.root != obj.provenance || !cap.grant.subset_of(cap.root.original_rights)
            || !cap.bound.subset_of(cap.root.original_rights) {
            return Err(Error::InvalidHandle);
        }
        // Defensive ancestry check. In ordinary operation revoke() removes all descendants.
        let mut next = cap.parent;
        let mut descendant = cap;
        for _ in 0..H {
            let Some(key) = next else { return Ok(cap); };
            let ancestor = self.handles.get(key.slot).ok_or(Error::InvalidHandle)?;
            if ancestor.generation != key.generation { return Err(Error::InvalidHandle); }
            let parent = ancestor.value.ok_or(Error::InvalidHandle)?;
            if parent.object != cap.object || parent.root != cap.root
                || !descendant.grant.subset_of(parent.grant)
                || !descendant.bound.subset_of(parent.bound) {
                return Err(Error::InvalidHandle);
            }
            descendant = parent;
            next = parent.parent;
        }
        Err(Error::InvalidHandle)
    }

    pub fn inspect(&self, caller: DomainId, handle: CapHandle) -> Result<CapView, Error> {
        let cap = self.resolve(caller, handle)?;
        let obj = self.object(cap.object).map_err(|_| Error::InvalidHandle)?;
        Ok(CapView {
            object: cap.object, kind: obj.kind, owner: cap.owner,
            root: cap.root, grant: cap.grant, bound: cap.bound,
        })
    }

    pub fn authorize(
        &self, caller: DomainId, handle: CapHandle, required: Rights,
    ) -> Result<CapView, Error> {
        let view = self.inspect(caller, handle)?;
        if !view.effective().contains(required) { return Err(Error::InsufficientRights); }
        Ok(view)
    }

    fn allocate_cap(&mut self, cap: CapRecord) -> Result<CapHandle, Error> {
        let hi = self.handles.iter().position(Slot::reusable).ok_or(Error::Full)?;
        let handle = CapHandle {
            slot: hi, generation: self.handles[hi].generation, domain: cap.owner,
        };
        self.handles[hi].value = Some(cap);
        Ok(handle)
    }

    fn attenuated(
        &self, caller: DomainId, source: CapHandle, grant: Rights, bound: Rights,
        mandatory: Rights,
    ) -> Result<CapRecord, Error> {
        let cap = self.resolve(caller, source)?;
        if !(cap.grant & cap.bound).contains(mandatory) {
            return Err(Error::InsufficientRights);
        }
        // Check both components, not just their intersection: prevents mutable
        // grant/bound co-inflation and preserves monotonic derivation chains.
        if !grant.subset_of(cap.grant) || !bound.subset_of(cap.bound)
            || !grant.subset_of(cap.root.original_rights)
            || !bound.subset_of(cap.root.original_rights) {
            return Err(Error::Amplification);
        }
        Ok(cap)
    }

    /// Derive a new local name; no right (including its bound) may be increased.
    pub fn derive(
        &mut self, caller: DomainId, source: CapHandle,
        grant: Rights, bound: Rights,
    ) -> Result<CapHandle, Error> {
        let parent = self.attenuated(caller, source, grant, bound, Rights::NONE)?;
        self.allocate_cap(CapRecord {
            object: parent.object, owner: caller, root: parent.root,
            grant, bound,
            parent: Some(CapKey { slot: source.slot, generation: source.generation }),
        })
    }

    pub fn prepare_transfer(
        &self, caller: DomainId, source: CapHandle, destination: DomainId,
        grant: Rights, bound: Rights,
    ) -> Result<PreparedTransfer, Error> {
        let parent = self.attenuated(caller, source, grant, bound, Rights::TRANSFER)?;
        Ok(PreparedTransfer {
            source, destination, object: parent.object,
            requested_grant: grant, requested_bound: bound,
        })
    }

    /// Must execute inside the kernel's cap-table critical section. Always
    /// rechecks live parent/provenance and receiver policy at the commit point.
    pub fn commit_transfer<P: TransferPolicy>(
        &mut self, caller: DomainId, transfer: PreparedTransfer, policy: &P,
    ) -> Result<CapHandle, Error> {
        let parent = self.attenuated(
            caller, transfer.source, transfer.requested_grant,
            transfer.requested_bound, Rights::TRANSFER,
        )?;
        if parent.object != transfer.object { return Err(Error::InvalidHandle); }
        if !policy.permit(
            caller, transfer.destination, parent.object,
            transfer.requested_grant & transfer.requested_bound,
        ) {
            return Err(Error::PolicyDenied);
        }
        self.allocate_cap(CapRecord {
            object: parent.object, owner: transfer.destination, root: parent.root,
            grant: transfer.requested_grant, bound: transfer.requested_bound,
            parent: Some(CapKey {
                slot: transfer.source.slot, generation: transfer.source.generation,
            }),
        })
    }

    /// Revoke the named capability and all descendants (including transfers).
    /// A single-threaded / externally locked slowpath avoids transfer/revoke races.
    pub fn revoke(&mut self, caller: DomainId, handle: CapHandle) -> Result<usize, Error> {
        self.resolve(caller, handle)?;
        let ancestor = CapKey { slot: handle.slot, generation: handle.generation };
        let mut selected = [false; H];
        for (i, marked) in selected.iter_mut().enumerate() {
            *marked = self.descends_from(i, ancestor);
        }
        let mut count = 0;
        for (i, marked) in selected.iter().enumerate() {
            if *marked {
                self.handles[i].retire();
                count += 1;
            }
        }
        Ok(count)
    }

    fn descends_from(&self, index: usize, ancestor: CapKey) -> bool {
        let mut cursor = Some(CapKey {
            slot: index, generation: self.handles[index].generation,
        });
        for _ in 0..H {
            let Some(key) = cursor else { return false; };
            if key == ancestor { return self.handles[index].value.is_some(); }
            let Some(slot) = self.handles.get(key.slot) else { return false; };
            if slot.generation != key.generation { return false; }
            let Some(cap) = slot.value else { return false; };
            cursor = cap.parent;
        }
        false
    }

    /// PRIVILEGED OBJECT LIFECYCLE HOOK; kernel must authorize the caller.
    /// Invalidates all caps/queued source handles. Reuse increments incarnation.
    pub fn retire_object(&mut self, id: ObjectId) -> Result<(), Error> {
        self.object(id)?;
        for slot in &mut self.handles {
            if slot.value.is_some_and(|cap| cap.object == id) {
                slot.retire();
            }
        }
        self.objects[id.slot].retire();
        Ok(())
    }
}

#[cfg(test)]
mod private_regression_tests {
    use super::*;

    #[test]
    fn mutated_cap_record_cannot_forge_root_provenance() {
        let owner = DomainId::new(1, 1).unwrap();
        let mut t: CapTable<2, 4> = CapTable::new();
        let (_, h) = t.bootstrap(owner, ObjectKind::Generic, Rights::READ).unwrap();
        let rec = t.handles[h.slot].value.as_mut().unwrap();
        rec.root.original_rights = Rights::READ | Rights::WRITE;
        rec.grant = Rights::READ | Rights::WRITE;
        rec.bound = Rights::READ | Rights::WRITE;
        // The forged cap copy does not match the canonical object-side root.
        assert_eq!(t.inspect(owner, h).unwrap_err(), Error::InvalidHandle);
    }

    #[test]
    fn mutated_grant_cannot_outgrow_canonical_root() {
        let owner = DomainId::new(1, 1).unwrap();
        let mut t: CapTable<2, 4> = CapTable::new();
        let (_, h) = t.bootstrap(owner, ObjectKind::Generic, Rights::READ).unwrap();
        let rec = t.handles[h.slot].value.as_mut().unwrap();
        rec.grant = Rights::READ | Rights::WRITE;
        rec.bound = Rights::READ | Rights::WRITE;
        assert_eq!(t.inspect(owner, h).unwrap_err(), Error::InvalidHandle);
    }

    #[test]
    fn saturated_handle_generation_is_never_reused() {
        let owner = DomainId::new(1, 1).unwrap();
        let mut t: CapTable<2, 2> = CapTable::new();
        let (_, original) = t.bootstrap(owner, ObjectKind::Generic, Rights::READ).unwrap();
        t.handles[original.slot].generation = u64::MAX - 1;
        let near_wrap = CapHandle { generation: u64::MAX - 1, ..original };
        assert_eq!(t.revoke(owner, near_wrap).unwrap(), 1);
        assert_eq!(t.handles[original.slot].generation, u64::MAX);
        assert!(!t.handles[original.slot].reusable());
        let (_, replacement) = t.bootstrap(owner, ObjectKind::Generic, Rights::READ).unwrap();
        assert_ne!(replacement.slot, original.slot);
    }
}
