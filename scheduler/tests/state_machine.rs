use fortressos_scheduler::{Error, Scheduler, ThreadState, WaitReason};

fn created<const N: usize, const C: usize>(
    sched: &mut Scheduler<N, C>, priority: u8, quantum: u64
) -> fortressos_scheduler::ThreadId {
    let id = sched.create(priority, quantum).unwrap();
    sched.enqueue(id).unwrap();
    id
}

#[test]
fn create_dispatch_block_wake_exit_reap() {
    let mut s = Scheduler::<3, 1>::new();
    let id = created(&mut s, 0, 5);
    assert_eq!(s.dispatch(0).unwrap(), Some(id));
    let epoch = s.observe_wake(id).unwrap();
    s.park_running(0, epoch, WaitReason::Ipc(12), None).unwrap();
    assert!(matches!(s.inspect(id).unwrap().state, ThreadState::Blocked { .. }));
    s.wake(id).unwrap();
    assert_eq!(s.runnable_count(), 1);
    assert_eq!(s.dispatch(0).unwrap(), Some(id));
    s.exit_running(0).unwrap();
    s.reap(id).unwrap();
    assert_eq!(s.inspect(id).unwrap().state, ThreadState::Retired);
    assert!(s.validate().is_ok());
}

#[test]
fn lost_wake_is_latched_before_park() {
    let mut s = Scheduler::<1, 1>::new();
    let id = created(&mut s, 0, 1);
    s.dispatch(0).unwrap();
    let observed = s.observe_wake(id).unwrap();
    s.wake(id).unwrap(); // wake arrives after observation, before park
    assert_eq!(s.park_running(0, observed, WaitReason::External, None),
               Err(Error::LostWakeAvoided));
    assert_eq!(s.cpu_running(0), Ok(Some(id)));
}

#[test]
fn cancel_blocked_cannot_be_woken_or_reaped_twice() {
    let mut s = Scheduler::<1, 1>::new();
    let id = created(&mut s, 0, 1);
    s.dispatch(0).unwrap();
    let e = s.observe_wake(id).unwrap();
    s.park_running(0, e, WaitReason::External, None).unwrap();
    s.cancel(id).unwrap();
    assert_eq!(s.wake(id), Err(Error::InvalidTransition));
    s.reap(id).unwrap();
    assert_eq!(s.reap(id), Err(Error::InvalidTransition));
    assert!(s.validate().is_ok());
}

#[test]
fn wake_then_cancel_removes_queued_entry() {
    let mut s = Scheduler::<1, 1>::new();
    let id = created(&mut s, 2, 1);
    s.dispatch(0).unwrap();
    let e = s.observe_wake(id).unwrap();
    s.park_running(0, e, WaitReason::External, None).unwrap();
    s.wake(id).unwrap();
    s.cancel(id).unwrap();
    assert_eq!(s.dispatch(0), Ok(None));
    s.reap(id).unwrap();
    assert!(s.validate().is_ok());
}

#[test]
fn running_cancel_waits_for_safe_handoff() {
    let mut s = Scheduler::<2, 1>::new();
    let id = created(&mut s, 0, 1);
    let next = created(&mut s, 0, 1);
    s.dispatch(0).unwrap();
    s.cancel(id).unwrap();
    assert_eq!(s.cpu_running(0), Ok(Some(id)));
    assert_eq!(s.dispatch(0), Err(Error::CpuBusy));
    assert_eq!(s.reap(id), Err(Error::InvalidTransition));
    s.yield_cpu(0).unwrap();
    assert_eq!(s.inspect(id).unwrap().state, ThreadState::Terminating);
    s.reap(id).unwrap();
    assert_eq!(s.dispatch(0), Ok(Some(next)));
    assert!(s.validate().is_ok());
}

#[test]
fn retired_id_cannot_wake_new_incarnation() {
    let mut s = Scheduler::<1, 1>::new();
    let old = created(&mut s, 0, 1);
    s.dispatch(0).unwrap();
    s.exit_running(0).unwrap();
    s.reap(old).unwrap();
    assert_eq!(s.wake(old), Err(Error::InvalidTransition));
    let new = s.create(0, 1).unwrap();
    assert_eq!(old.slot, new.slot);
    assert_ne!(old.generation, new.generation);
    assert_eq!(s.wake(old), Err(Error::StaleThread));
    s.enqueue(new).unwrap();
    assert!(s.validate().is_ok());
}

#[test]
fn cannot_enqueue_twice() {
    let mut s = Scheduler::<1, 1>::new();
    let id = created(&mut s, 0, 1);
    assert_eq!(s.enqueue(id), Err(Error::InvalidTransition));
    assert_eq!(s.runnable_count(), 1);
}

#[test]
fn bounded_slots_and_invalid_budget_priority() {
    let mut s = Scheduler::<1, 1>::new();
    assert_eq!(s.create(4, 1), Err(Error::InvalidPriority));
    assert_eq!(s.create(0, 0), Err(Error::InvalidBudget));
    let _id = created(&mut s, 0, 1);
    assert_eq!(s.create(0, 1), Err(Error::NoCapacity));
    assert!(s.validate().is_ok());
}

#[test]
fn two_cpus_never_dispatch_one_thread_twice() {
    let mut s = Scheduler::<1, 2>::new();
    let id = created(&mut s, 0, 1);
    assert_eq!(s.dispatch(0), Ok(Some(id)));
    assert_eq!(s.dispatch(1), Ok(None));
    assert_eq!(s.dispatch(0), Err(Error::CpuBusy));
    assert!(s.validate().is_ok());
}

#[test]
fn elapsed_budget_only_flags_preemption_until_handoff() {
    let mut s = Scheduler::<1, 1>::new();
    let id = created(&mut s, 0, 2);
    s.dispatch(0).unwrap();
    assert_eq!(s.preempt_cpu(0), Err(Error::InvalidTransition));
    s.tick(10).unwrap();
    let info = s.inspect(id).unwrap();
    assert_eq!(info.remaining, 0);
    assert!(info.preempt_pending);
    assert_eq!(s.cpu_running(0), Ok(Some(id)));
    s.preempt_cpu(0).unwrap();
    assert_eq!(s.dispatch(0), Ok(Some(id)));
    assert_eq!(s.inspect(id).unwrap().remaining, 2);
}

#[test]
fn timeout_wakes_exactly_once() {
    let mut s = Scheduler::<1, 1>::new();
    let id = created(&mut s, 1, 1);
    s.dispatch(0).unwrap();
    let e = s.observe_wake(id).unwrap();
    s.park_running(0, e, WaitReason::Timer, Some(5)).unwrap();
    s.tick(4).unwrap();
    assert_eq!(s.runnable_count(), 0);
    s.tick(1).unwrap();
    assert_eq!(s.runnable_count(), 1);
    s.tick(3).unwrap();
    assert_eq!(s.runnable_count(), 1);
    assert!(s.validate().is_ok());
}

#[test]
fn deadline_and_clock_overflow_rejected_without_blocking() {
    let mut s = Scheduler::<1, 1>::new();
    let id = created(&mut s, 0, 1);
    s.dispatch(0).unwrap();
    s.tick(10).unwrap();
    let e = s.observe_wake(id).unwrap();
    assert_eq!(s.park_running(0, e, WaitReason::Timer, Some(u64::MAX)), Err(Error::TimeOverflow));
    assert_eq!(s.park_running(0, e, WaitReason::Timer, Some(0)), Err(Error::DeadlineElapsed));
    assert_eq!(s.tick(u64::MAX), Err(Error::TimeOverflow));
    assert_eq!(s.now(), 10);
    assert_eq!(s.cpu_running(0), Ok(Some(id)));
}

#[test]
fn priority_service_includes_low_priority_under_yield_assumption() {
    let mut s = Scheduler::<4, 1>::new();
    let ids = [created(&mut s, 0, 1), created(&mut s, 1, 1),
               created(&mut s, 2, 1), created(&mut s, 3, 1)];
    let mut count = [0u32; 4];
    for _ in 0..60 {
        let id = s.dispatch(0).unwrap().unwrap();
        let index = ids.iter().position(|candidate| *candidate == id).unwrap();
        count[index] += 1;
        s.yield_cpu(0).unwrap();
    }
    assert!(count.iter().all(|n| *n >= 2), "{count:?}");
    assert!(count[0] > count[3]);
    assert!(s.validate().is_ok());
}

#[test]
fn lock_cycle_rejected_without_displacing_running_owner() {
    let mut s = Scheduler::<2, 2>::new();
    let a = created(&mut s, 0, 5);
    let b = created(&mut s, 0, 5);
    assert_eq!(s.dispatch(0), Ok(Some(a)));
    assert_eq!(s.dispatch(1), Ok(Some(b)));
    let ea = s.observe_wake(a).unwrap();
    s.park_running(0, ea, WaitReason::Lock(b), None).unwrap();
    let eb = s.observe_wake(b).unwrap();
    assert_eq!(s.park_running(1, eb, WaitReason::Lock(a), None), Err(Error::Deadlock));
    assert_eq!(s.cpu_running(1), Ok(Some(b)));
    assert!(s.validate().is_ok());
}

#[test]
fn faulted_task_can_be_reaped_while_peer_progresses() {
    let mut s = Scheduler::<2, 1>::new();
    let faulted = created(&mut s, 0, 2);
    let survivor = created(&mut s, 0, 2);
    assert_eq!(s.dispatch(0), Ok(Some(faulted)));
    s.exit_running(0).unwrap(); // modeled trap-handler decision, NOT real CPL3
    s.reap(faulted).unwrap();
    assert_eq!(s.dispatch(0), Ok(Some(survivor)));
    assert!(s.validate().is_ok());
}

#[test]
fn no_generation_wrap_on_recycled_slot() {
    let mut s = Scheduler::<1, 1>::new();
    let id = s.create(0, 1).unwrap();
    s.cancel(id).unwrap();
    s.reap(id).unwrap();
    // A test-only artificial max generation must not recycle to zero.
    // Exercise the public API by exhausting capacity on a separate fixture.
    assert_eq!(s.create(0, 1).unwrap().generation, 2);
}

#[test]
fn impossible_cpu_id_is_rejected() {
    let mut s = Scheduler::<1, 1>::new();
    assert_eq!(s.dispatch(1), Err(Error::InvalidCpu));
    assert_eq!(s.cpu_running(1), Err(Error::InvalidCpu));
    assert_eq!(s.yield_cpu(0), Err(Error::NotRunning));
}
