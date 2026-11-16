#![no_std]
#![forbid(unsafe_code)]
//! Deterministic, bounded scheduler reference (NOT a CPU context switch).
//! All methods require one external serialized scheduler lock. SMP is NOT proven.

pub const PRIORITY_LEVELS: usize = 4;
// Repeating weighted fair *dispatch* slots; no wall-time progress guarantee.
const SERVICE: [usize; 10] = [0, 0, 0, 0, 1, 1, 1, 2, 2, 3];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadId {
    pub slot: usize,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitReason {
    External,
    Timer,
    Ipc(u64),
    Lock(ThreadId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Vacant,
    New,
    Runnable,
    Running { cpu: usize },
    Blocked { reason: WaitReason, deadline: Option<u64> },
    Terminating,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoCapacity,
    InvalidPriority,
    InvalidBudget,
    InvalidCpu,
    CpuBusy,
    NotRunning,
    StaleThread,
    InvalidTransition,
    AlreadyQueued,
    QueueFull,
    LostWakeAvoided,
    DeadlineElapsed,
    TimeOverflow,
    EpochOverflow,
    GenerationExhausted,
    InvalidLockOwner,
    Deadlock,
    InvariantViolation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadView {
    pub state: ThreadState,
    pub priority: u8,
    pub remaining: u64,
    pub wake_epoch: u64,
    pub cancel_pending: bool,
    pub preempt_pending: bool,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    state: ThreadState,
    priority: u8,
    quantum: u64,
    remaining: u64,
    wake_epoch: u64,
    cancel_pending: bool,
    preempt_pending: bool,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 0,
        state: ThreadState::Vacant,
        priority: 0,
        quantum: 0,
        remaining: 0,
        wake_epoch: 0,
        cancel_pending: false,
        preempt_pending: false,
    };
    fn view(self) -> ThreadView {
        ThreadView {
            state: self.state,
            priority: self.priority,
            remaining: self.remaining,
            wake_epoch: self.wake_epoch,
            cancel_pending: self.cancel_pending,
            preempt_pending: self.preempt_pending,
        }
    }
}

// One bounded FIFO for each priority, with O(N) removal for cancellation.
#[derive(Clone, Copy)]
struct ReadyQueue<const N: usize> {
    entries: [Option<ThreadId>; N],
    len: usize,
}

impl<const N: usize> ReadyQueue<N> {
    const fn new() -> Self { Self { entries: [None; N], len: 0 } }

    fn push(&mut self, id: ThreadId) -> Result<(), Error> {
        if self.entries[..self.len].iter().any(|x| *x == Some(id)) {
            return Err(Error::AlreadyQueued);
        }
        if self.len == N { return Err(Error::QueueFull); }
        self.entries[self.len] = Some(id);
        self.len += 1;
        Ok(())
    }

    fn remove_at(&mut self, pos: usize) -> Option<ThreadId> {
        if pos >= self.len { return None; }
        let found = self.entries[pos];
        for i in (pos + 1)..self.len { self.entries[i - 1] = self.entries[i]; }
        self.len -= 1;
        self.entries[self.len] = None;
        found
    }

    fn pop(&mut self) -> Option<ThreadId> { self.remove_at(0) }

    fn remove(&mut self, id: ThreadId) -> bool {
        let pos = self.entries[..self.len].iter().position(|x| *x == Some(id));
        match pos { Some(i) => { self.remove_at(i); true }, None => false }
    }
}

/// Pure, deterministic, single-lock scheduler reference. No heap allocation.
/// CPU slots are *logical*: no interrupt masking, CR3, trapframe or atomicity.
pub struct Scheduler<const N: usize, const CPUS: usize> {
    slots: [Slot; N],
    ready: [ReadyQueue<N>; PRIORITY_LEVELS],
    current: [Option<ThreadId>; CPUS],
    now: u64,
    service_cursor: usize,
}

impl<const N: usize, const CPUS: usize> Default for Scheduler<N, CPUS> {
    fn default() -> Self { Self::new() }
}

impl<const N: usize, const CPUS: usize> Scheduler<N, CPUS> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; N],
            ready: [ReadyQueue::new(); PRIORITY_LEVELS],
            current: [None; CPUS],
            now: 0,
            service_cursor: 0,
        }
    }

    pub fn now(&self) -> u64 { self.now }

    fn slot_index(&self, id: ThreadId) -> Result<usize, Error> {
        if id.generation == 0 { return Err(Error::StaleThread); }
        match self.slots.get(id.slot) {
            Some(s) if s.generation == id.generation && s.state != ThreadState::Vacant =>
                Ok(id.slot),
            _ => Err(Error::StaleThread),
        }
    }

    pub fn inspect(&self, id: ThreadId) -> Result<ThreadView, Error> {
        Ok(self.slots[self.slot_index(id)?].view())
    }

    pub fn cpu_running(&self, cpu: usize) -> Result<Option<ThreadId>, Error> {
        self.current.get(cpu).copied().ok_or(Error::InvalidCpu)
    }

    /// Returns New, requiring an explicit enqueue. IDs are never silently recycled.
    pub fn create(&mut self, priority: u8, quantum: u64) -> Result<ThreadId, Error> {
        if priority as usize >= PRIORITY_LEVELS { return Err(Error::InvalidPriority); }
        if quantum == 0 { return Err(Error::InvalidBudget); }
        let mut index = None;
        let mut exhausted = false;
        for i in 0..N {
            let slot = self.slots[i];
            if matches!(slot.state, ThreadState::Vacant | ThreadState::Retired) {
                if slot.generation == u64::MAX { exhausted = true; continue; }
                index = Some(i);
                break;
            }
        }
        let i = match index {
            Some(i) => i,
            None if exhausted => return Err(Error::GenerationExhausted),
            None => return Err(Error::NoCapacity),
        };
        let generation = self.slots[i].generation + 1;
        self.slots[i] = Slot {
            generation, state: ThreadState::New, priority, quantum,
            remaining: quantum, wake_epoch: 0, cancel_pending: false,
            preempt_pending: false,
        };
        Ok(ThreadId { slot: i, generation })
    }

    /// Only New -> Runnable. Waking blocked threads must go through wake().
    pub fn enqueue(&mut self, id: ThreadId) -> Result<(), Error> {
        let i = self.slot_index(id)?;
        if self.slots[i].state != ThreadState::New { return Err(Error::InvalidTransition); }
        let priority = self.slots[i].priority as usize;
        self.ready[priority].push(id)?;
        self.slots[i].state = ThreadState::Runnable;
        Ok(())
    }

    pub fn dispatch(&mut self, cpu: usize) -> Result<Option<ThreadId>, Error> {
        if cpu >= CPUS { return Err(Error::InvalidCpu); }
        if self.current[cpu].is_some() { return Err(Error::CpuBusy); }
        let mut chosen = None;
        for offset in 0..SERVICE.len() {
            let cursor = (self.service_cursor + offset) % SERVICE.len();
            let priority = SERVICE[cursor];
            if self.ready[priority].len != 0 {
                chosen = Some((priority, cursor));
                break;
            }
        }
        let Some((priority, cursor)) = chosen else { return Ok(None); };
        let id = self.ready[priority].entries[0].ok_or(Error::InvariantViolation)?;
        let i = self.slot_index(id)?;
        if self.slots[i].state != ThreadState::Runnable ||
            self.slots[i].priority as usize != priority {
            return Err(Error::InvariantViolation);
        }
        self.ready[priority].pop();
        self.service_cursor = (cursor + 1) % SERVICE.len();
        self.slots[i].state = ThreadState::Running { cpu };
        if self.slots[i].remaining == 0 { self.slots[i].remaining = self.slots[i].quantum; }
        self.slots[i].preempt_pending = false;
        self.current[cpu] = Some(id);
        Ok(Some(id))
    }

    fn running_index(&self, cpu: usize) -> Result<(ThreadId, usize), Error> {
        let id = self.cpu_running(cpu)?.ok_or(Error::NotRunning)?;
        let i = self.slot_index(id)?;
        if self.slots[i].state != (ThreadState::Running { cpu }) {
            return Err(Error::InvariantViolation);
        }
        Ok((id, i))
    }

    /// Cooperative handoff, or architecturally safe post-trap handoff.
    pub fn yield_cpu(&mut self, cpu: usize) -> Result<ThreadId, Error> {
        let (id, i) = self.running_index(cpu)?;
        if self.slots[i].cancel_pending {
            self.slots[i].state = ThreadState::Terminating;
        } else {
            self.ready[self.slots[i].priority as usize].push(id)?;
            self.slots[i].state = ThreadState::Runnable;
        }
        self.slots[i].preempt_pending = false;
        self.current[cpu] = None;
        Ok(id)
    }

    /// A timer tick only requests preemption. Assembly/IRQ owner must save context
    /// and call this only after the state is safe to relinquish.
    pub fn preempt_cpu(&mut self, cpu: usize) -> Result<ThreadId, Error> {
        let (_, i) = self.running_index(cpu)?;
        if !self.slots[i].preempt_pending { return Err(Error::InvalidTransition); }
        self.yield_cpu(cpu)
    }

    pub fn exit_running(&mut self, cpu: usize) -> Result<ThreadId, Error> {
        let (id, i) = self.running_index(cpu)?;
        self.slots[i].state = ThreadState::Terminating;
        self.slots[i].cancel_pending = false;
        self.slots[i].preempt_pending = false;
        self.current[cpu] = None;
        Ok(id)
    }

    /// Observation must be done before trying to sleep while holding the same
    /// external lock as wake(), or the caller must revalidate its wait predicate.
    pub fn observe_wake(&self, id: ThreadId) -> Result<u64, Error> {
        let i = self.slot_index(id)?;
        if matches!(self.slots[i].state, ThreadState::Terminating | ThreadState::Retired) {
            return Err(Error::InvalidTransition);
        }
        Ok(self.slots[i].wake_epoch)
    }

    /// Running -> Blocked, with atomic observed-epoch comparison.
    /// A concurrent wake-before-park is remembered and causes LostWakeAvoided.
    /// A relative deadline of zero is rejected; arithmetic wraps are rejected.
    pub fn park_running(
        &mut self,
        cpu: usize,
        observed_epoch: u64,
        reason: WaitReason,
        relative_timeout: Option<u64>,
    ) -> Result<ThreadId, Error> {
        let (id, i) = self.running_index(cpu)?;
        if self.slots[i].cancel_pending { return Err(Error::InvalidTransition); }
        if observed_epoch != self.slots[i].wake_epoch { return Err(Error::LostWakeAvoided); }
        let deadline = match relative_timeout {
            None => None,
            Some(0) => return Err(Error::DeadlineElapsed),
            Some(t) => Some(self.now.checked_add(t).ok_or(Error::TimeOverflow)?),
        };
        if let WaitReason::Lock(owner) = reason { self.check_lock_dependency(id, owner)?; }
        self.slots[i].state = ThreadState::Blocked { reason, deadline };
        self.current[cpu] = None;
        Ok(id)
    }

    fn check_lock_dependency(&self, waiter: ThreadId, owner: ThreadId) -> Result<(), Error> {
        let mut next = owner;
        // Any cycle reachable from owner, including one that already exists,
        // is rejected; no unbounded graph traversal or false "deadlock recovery".
        for _ in 0..=N {
            if next == waiter { return Err(Error::Deadlock); }
            let i = self.slot_index(next).map_err(|_| Error::InvalidLockOwner)?;
            if matches!(self.slots[i].state, ThreadState::Terminating | ThreadState::Retired) {
                return Err(Error::InvalidLockOwner);
            }
            match self.slots[i].state {
                ThreadState::Blocked { reason: WaitReason::Lock(upstream), .. } =>
                    next = upstream,
                _ => return Ok(()),
            }
        }
        Err(Error::Deadlock)
    }

    /// Wake notifications are latched for Running/New/Runnable threads and
    /// de-duplicate blocked->ready transitions. Caller owns wake authorization.
    pub fn wake(&mut self, id: ThreadId) -> Result<(), Error> {
        let i = self.slot_index(id)?;
        let next_epoch = self.slots[i].wake_epoch.checked_add(1).ok_or(Error::EpochOverflow)?;
        match self.slots[i].state {
            ThreadState::Terminating | ThreadState::Retired | ThreadState::Vacant =>
                return Err(Error::InvalidTransition),
            ThreadState::Blocked { .. } => {
                self.ready[self.slots[i].priority as usize].push(id)?;
                self.slots[i].state = ThreadState::Runnable;
            }
            ThreadState::New | ThreadState::Runnable | ThreadState::Running { .. } => {}
        }
        self.slots[i].wake_epoch = next_epoch;
        Ok(())
    }

    /// Cancel Running: only sets pending, retains CPU ownership until yield/exit.
    /// Cancel queued/blocked/new: enters Terminating immediately.
    pub fn cancel(&mut self, id: ThreadId) -> Result<(), Error> {
        let i = self.slot_index(id)?;
        match self.slots[i].state {
            ThreadState::Running { .. } => { self.slots[i].cancel_pending = true; }
            ThreadState::Runnable => {
                if !self.ready[self.slots[i].priority as usize].remove(id) {
                    return Err(Error::InvariantViolation);
                }
                self.slots[i].state = ThreadState::Terminating;
            }
            ThreadState::New | ThreadState::Blocked { .. } =>
                self.slots[i].state = ThreadState::Terminating,
            _ => return Err(Error::InvalidTransition),
        }
        Ok(())
    }

    pub fn reap(&mut self, id: ThreadId) -> Result<(), Error> {
        let i = self.slot_index(id)?;
        if self.slots[i].state != ThreadState::Terminating {
            return Err(Error::InvalidTransition);
        }
        self.slots[i].state = ThreadState::Retired;
        self.slots[i].remaining = 0;
        self.slots[i].cancel_pending = false;
        self.slots[i].preempt_pending = false;
        Ok(())
    }

    /// Accounts elapsed ticks and wakes timeouts; NEVER switches CPU context.
    /// tick(0) is allowed; running budgets saturate to zero, never underflow.
    pub fn tick(&mut self, delta: u64) -> Result<(), Error> {
        let next = self.now.checked_add(delta).ok_or(Error::TimeOverflow)?;
        // Preflight timer wakes before mutating the clock or CPU budgets.
        // A counter at MAX must fail closed without partially committing a tick.
        for slot in &self.slots {
            if let ThreadState::Blocked { deadline: Some(deadline), .. } = slot.state {
                if deadline <= next && slot.wake_epoch == u64::MAX {
                    return Err(Error::EpochOverflow);
                }
            }
        }
        self.now = next;
        for cpu in 0..CPUS {
            if let Some(id) = self.current[cpu] {
                let i = self.slot_index(id)?;
                self.slots[i].remaining = self.slots[i].remaining.saturating_sub(delta);
                if self.slots[i].remaining == 0 { self.slots[i].preempt_pending = true; }
            }
        }
        for i in 0..N {
            if let ThreadState::Blocked { deadline: Some(deadline), .. } = self.slots[i].state {
                if deadline <= next {
                    let id = ThreadId { slot: i, generation: self.slots[i].generation };
                    self.wake(id)?;
                }
            }
        }
        Ok(())
    }

    pub fn runnable_count(&self) -> usize {
        self.ready.iter().map(|queue| queue.len).sum()
    }

    /// Expensive host/reference invariant scan, not a synchronization primitive.
    pub fn validate(&self) -> Result<(), Error> {
        for (prio, queue) in self.ready.iter().enumerate() {
            if queue.len > N { return Err(Error::InvariantViolation); }
            for item in &queue.entries[..queue.len] {
                let id = item.ok_or(Error::InvariantViolation)?;
                let i = self.slot_index(id)?;
                if self.slots[i].state != ThreadState::Runnable ||
                    self.slots[i].priority as usize != prio {
                    return Err(Error::InvariantViolation);
                }
            }
            if queue.entries[queue.len..].iter().any(Option::is_some) {
                return Err(Error::InvariantViolation);
            }
        }
        for i in 0..N {
            let id = ThreadId { slot: i, generation: self.slots[i].generation };
            let queued = self.ready.iter()
                .flat_map(|q| q.entries[..q.len].iter())
                .filter(|item| **item == Some(id)).count();
            let running = self.current.iter().filter(|item| **item == Some(id)).count();
            match self.slots[i].state {
                ThreadState::Runnable if queued == 1 && running == 0 => {}
                ThreadState::Running { cpu } if queued == 0 && running == 1 &&
                    self.current.get(cpu) == Some(&Some(id)) => {}
                ThreadState::Vacant | ThreadState::New | ThreadState::Blocked { .. } |
                ThreadState::Terminating | ThreadState::Retired if queued == 0 && running == 0 => {}
                _ => return Err(Error::InvariantViolation),
            }
        }
        for (cpu, item) in self.current.iter().enumerate() {
            if let Some(id) = item {
                let i = self.slot_index(*id)?;
                if self.slots[i].state != (ThreadState::Running { cpu }) {
                    return Err(Error::InvariantViolation);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod internal_negative_tests {
    use super::*;

    #[test]
    fn queue_full_and_duplicate_do_not_corrupt_length() {
        let mut q = ReadyQueue::<1>::new();
        let a = ThreadId { slot: 0, generation: 1 };
        let b = ThreadId { slot: 0, generation: 2 };
        assert_eq!(q.push(a), Ok(()));
        assert_eq!(q.push(a), Err(Error::AlreadyQueued));
        assert_eq!(q.push(b), Err(Error::QueueFull));
        assert_eq!(q.len, 1);
        assert_eq!(q.pop(), Some(a));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn max_generation_can_never_wrap_or_reuse() {
        let mut s = Scheduler::<1, 1>::new();
        s.slots[0].state = ThreadState::Retired;
        s.slots[0].generation = u64::MAX;
        assert_eq!(s.create(0, 1), Err(Error::GenerationExhausted));
        assert_eq!(s.slots[0].generation, u64::MAX);
    }

    #[test]
    fn timed_wake_epoch_overflow_keeps_clock_and_state_unchanged() {
        let mut s = Scheduler::<1, 1>::new();
        let id = s.create(0, 1).unwrap();
        s.enqueue(id).unwrap();
        s.dispatch(0).unwrap();
        let epoch = s.observe_wake(id).unwrap();
        s.park_running(0, epoch, WaitReason::Timer, Some(1)).unwrap();
        s.slots[id.slot].wake_epoch = u64::MAX;
        assert_eq!(s.tick(1), Err(Error::EpochOverflow));
        assert_eq!(s.now(), 0);
        assert!(matches!(s.slots[id.slot].state, ThreadState::Blocked { .. }));
        assert!(s.validate().is_ok());
    }

    #[test]
    fn invariant_detector_rejects_double_run_on_two_cpus() {
        let mut s = Scheduler::<1, 2>::new();
        let id = s.create(0, 1).unwrap();
        s.enqueue(id).unwrap();
        s.dispatch(0).unwrap();
        s.current[1] = Some(id); // Inject a forbidden corrupted state.
        assert_eq!(s.validate(), Err(Error::InvariantViolation));
    }

    #[test]
    fn invariant_detector_rejects_duplicate_ready_entries() {
        let mut s = Scheduler::<2, 1>::new();
        let id = s.create(0, 1).unwrap();
        s.enqueue(id).unwrap();
        s.ready[0].entries[1] = Some(id); // Deliberate corruption.
        s.ready[0].len = 2;
        assert_eq!(s.validate(), Err(Error::InvariantViolation));
    }

    #[test]
    fn wake_epoch_wrap_is_rejected_without_enqueue() {
        let mut s = Scheduler::<1, 1>::new();
        let id = s.create(0, 1).unwrap();
        s.enqueue(id).unwrap();
        s.dispatch(0).unwrap();
        let e = s.observe_wake(id).unwrap();
        s.park_running(0, e, WaitReason::External, None).unwrap();
        s.slots[id.slot].wake_epoch = u64::MAX;
        assert_eq!(s.wake(id), Err(Error::EpochOverflow));
        assert_eq!(s.runnable_count(), 0);
        assert!(s.validate().is_ok());
    }
}
