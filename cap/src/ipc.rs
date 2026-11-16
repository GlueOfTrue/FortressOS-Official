//! Reference bounded, copying IPC slowpath. No scheduler, waitqueue, shared pages or syscall ABI.
//! Serialize table + IPC operations under the same kernel lock; callbacks are trusted policy.

use crate::{CapHandle, CapTable, DomainId, Error as CapError, ObjectId, ObjectKind, Rights};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    Cap(CapError),
    TooLarge,
    Full,
    RequestExhausted,
    Expired,
    NotFound,
    NotReady,
    WrongPeer,
    WrongEndpoint,
    DuplicateReply,
    PolicyDenied,
}
impl From<CapError> for IpcError {
    fn from(e: CapError) -> Self { Self::Cap(e) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestId(u64);
impl RequestId {
    pub const fn value(self) -> u64 { self.0 }
}

/// The policy implementation belongs to 07. None of these hooks is a MAC
/// decision, and a permanently-Allow policy is unsuitable for production.
pub trait IpcPolicy {
    fn allow_enqueue(&self, sender: DomainId, receiver: DomainId, endpoint: ObjectId) -> bool;
    fn allow_delivery(&self, sender: DomainId, receiver: DomainId, endpoint: ObjectId) -> bool;
    fn allow_response(&self, sender: DomainId, receiver: DomainId, endpoint: ObjectId) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State { Queued, InFlight, Replied }

#[derive(Clone, Copy, Debug)]
struct Request<const BYTES: usize> {
    id: RequestId,
    from: DomainId,
    to: DomainId,
    endpoint: ObjectId,
    sender_cap: CapHandle,
    deadline: u64,
    state: State,
    body: [u8; BYTES],
    len: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Delivery<const BYTES: usize> {
    pub id: RequestId,
    pub from: DomainId,
    pub len: usize,
    pub bytes: [u8; BYTES],
}
impl<const BYTES: usize> Delivery<BYTES> {
    pub fn payload(&self) -> &[u8] { &self.bytes[..self.len] }
}

#[derive(Clone, Copy, Debug)]
pub struct Response<const BYTES: usize> {
    pub id: RequestId,
    pub len: usize,
    pub bytes: [u8; BYTES],
}
impl<const BYTES: usize> Response<BYTES> {
    pub fn payload(&self) -> &[u8] { &self.bytes[..self.len] }
}

pub struct Ipc<const REQUESTS: usize, const BYTES: usize> {
    entries: [Option<Request<BYTES>>; REQUESTS],
    next_id: u64,
}
impl<const Q: usize, const B: usize> Default for Ipc<Q, B> {
    fn default() -> Self { Self::new() }
}

impl<const Q: usize, const B: usize> Ipc<Q, B> {
    pub fn new() -> Self {
        Self { entries: core::array::from_fn(|_| None), next_id: 1 }
    }

    pub fn outstanding(&self) -> usize { self.entries.iter().filter(|r| r.is_some()).count() }

    fn endpoint<const O: usize, const H: usize>(
        table: &CapTable<O, H>, domain: DomainId, cap: CapHandle, need: Rights,
    ) -> Result<ObjectId, IpcError> {
        let view = table.authorize(domain, cap, need)?;
        if view.kind != ObjectKind::Endpoint { return Err(CapError::NotEndpoint.into()); }
        Ok(view.object)
    }

    fn valid_sender<const O: usize, const H: usize>(
        table: &CapTable<O, H>, req: Request<B>,
    ) -> bool {
        Self::endpoint(table, req.from, req.sender_cap, Rights::SEND)
            .is_ok_and(|object| object == req.endpoint)
    }

    /// Timeout uses a monotonic kernel-supplied clock (not wall time). All
    /// request slots, including in-flight replies, are quota-accounted.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut expired = 0;
        for slot in &mut self.entries {
            if slot.is_some_and(|r| now >= r.deadline) {
                *slot = None;
                expired += 1;
            }
        }
        expired
    }

    /// Remove records whose originating cap/object is no longer authoritative.
    /// Also invoked on enqueue to release capacity after a completed revoke.
    pub fn reap_invalid<const O: usize, const H: usize>(
        &mut self, table: &CapTable<O, H>,
    ) -> usize {
        let mut reaped = 0;
        for slot in &mut self.entries {
            if slot.is_some_and(|r| !Self::valid_sender(table, r)) {
                *slot = None;
                reaped += 1;
            }
        }
        reaped
    }

    pub fn enqueue<const O: usize, const H: usize, P: IpcPolicy>(
        &mut self, table: &CapTable<O, H>, sender: DomainId, send_cap: CapHandle,
        receiver: DomainId, payload: &[u8], now: u64, deadline: u64, policy: &P,
    ) -> Result<RequestId, IpcError> {
        self.expire(now);
        self.reap_invalid(table);
        if now >= deadline { return Err(IpcError::Expired); }
        if payload.len() > B { return Err(IpcError::TooLarge); }
        let endpoint = Self::endpoint(table, sender, send_cap, Rights::SEND)?;
        let view = table.inspect(sender, send_cap)?;
        // This prototype has one designated receiver: the endpoint's founder.
        // Arbitrary receiver selection is NOT inferred from message bytes.
        if receiver != view.root.founder() { return Err(IpcError::WrongPeer); }
        if !policy.allow_enqueue(sender, receiver, endpoint) {
            return Err(IpcError::PolicyDenied);
        }
        let free = self.entries.iter().position(Option::is_none).ok_or(IpcError::Full)?;
        let next = self.next_id.checked_add(1).ok_or(IpcError::RequestExhausted)?;
        let id = RequestId(self.next_id);
        let mut body = [0u8; B];
        body[..payload.len()].copy_from_slice(payload);
        self.entries[free] = Some(Request {
            id, from: sender, to: receiver, endpoint, sender_cap: send_cap,
            deadline, state: State::Queued, body, len: payload.len(),
        });
        self.next_id = next;
        Ok(id)
    }

    pub fn receive<const O: usize, const H: usize, P: IpcPolicy>(
        &mut self, table: &CapTable<O, H>, receiver: DomainId,
        recv_cap: CapHandle, now: u64, policy: &P,
    ) -> Result<Option<Delivery<B>>, IpcError> {
        self.expire(now);
        let endpoint = Self::endpoint(table, receiver, recv_cap, Rights::RECEIVE)?;
        loop {
            // FIFO by monotonic request id, independent of slot reuse.
            let oldest = self.entries.iter().enumerate()
                .filter_map(|(i, r)| r.filter(|r| r.state == State::Queued
                    && r.to == receiver && r.endpoint == endpoint).map(|r| (i, r.id.0)))
                .min_by_key(|(_, id)| *id).map(|(i, _)| i);
            let Some(index) = oldest else { return Ok(None); };
            let req = self.entries[index].expect("selected occupied request");
            if !Self::valid_sender(table, req)
                || !policy.allow_delivery(req.from, receiver, endpoint) {
                self.entries[index] = None;
                continue;
            }
            self.entries[index].as_mut().expect("selected occupied request").state = State::InFlight;
            return Ok(Some(Delivery {
                id: req.id, from: req.from, len: req.len, bytes: req.body,
            }));
        }
    }

    pub fn reply<const O: usize, const H: usize, P: IpcPolicy>(
        &mut self, table: &CapTable<O, H>, responder: DomainId,
        reply_cap: CapHandle, request_id: RequestId, payload: &[u8],
        now: u64, policy: &P,
    ) -> Result<(), IpcError> {
        self.expire(now);
        if payload.len() > B { return Err(IpcError::TooLarge); }
        let endpoint = Self::endpoint(table, responder, reply_cap, Rights::REPLY)?;
        let index = self.entries.iter().position(|r| r.is_some_and(|r| r.id == request_id))
            .ok_or(IpcError::NotFound)?;
        let req = self.entries[index].expect("occupied request");
        if req.to != responder { return Err(IpcError::WrongPeer); }
        if req.endpoint != endpoint { return Err(IpcError::WrongEndpoint); }
        if req.state == State::Replied { return Err(IpcError::DuplicateReply); }
        if req.state != State::InFlight { return Err(IpcError::NotReady); }
        if !Self::valid_sender(table, req)
            || !policy.allow_response(req.from, responder, endpoint) {
            self.entries[index] = None;
            return Err(IpcError::PolicyDenied);
        }
        let slot = self.entries[index].as_mut().expect("occupied request");
        slot.body.fill(0);
        slot.body[..payload.len()].copy_from_slice(payload);
        slot.len = payload.len();
        slot.state = State::Replied;
        Ok(())
    }

    /// A request id is correlation only, never a capability. Full sender
    /// incarnation, original send capability and current policy are rechecked.
    pub fn collect<const O: usize, const H: usize, P: IpcPolicy>(
        &mut self, table: &CapTable<O, H>, sender: DomainId,
        request_id: RequestId, now: u64, policy: &P,
    ) -> Result<Response<B>, IpcError> {
        self.expire(now);
        let index = self.entries.iter().position(|r| r.is_some_and(|r| r.id == request_id))
            .ok_or(IpcError::NotFound)?;
        let req = self.entries[index].expect("occupied request");
        if req.from != sender { return Err(IpcError::WrongPeer); }
        if req.state != State::Replied { return Err(IpcError::NotReady); }
        if !Self::valid_sender(table, req)
            || !policy.allow_response(sender, req.to, req.endpoint) {
            self.entries[index] = None;
            return Err(IpcError::PolicyDenied);
        }
        self.entries[index] = None;
        Ok(Response { id: req.id, len: req.len, bytes: req.body })
    }

    /// Cancellation wins if serialized before reply/collect. Any late responder
    /// observes NotFound; ids never wrap into a newly allocated request.
    pub fn cancel(&mut self, sender: DomainId, request_id: RequestId) -> Result<(), IpcError> {
        let index = self.entries.iter().position(|r| r.is_some_and(|r| r.id == request_id))
            .ok_or(IpcError::NotFound)?;
        if self.entries[index].expect("occupied request").from != sender {
            return Err(IpcError::WrongPeer);
        }
        self.entries[index] = None;
        Ok(())
    }
}
