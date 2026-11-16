use fortress_cap_ipc::{
    CapTable, DomainId, Error, ObjectId, ObjectKind, Rights, TransferPolicy,
};
use fortress_cap_ipc::ipc::{Ipc, IpcError, IpcPolicy};

fn dom(slot: u32, generation: u64) -> DomainId {
    DomainId::new(slot, generation).unwrap()
}

struct Allow;
impl TransferPolicy for Allow {
    fn permit(&self, _: DomainId, _: DomainId, _: ObjectId, _: Rights) -> bool { true }
}
impl IpcPolicy for Allow {
    fn allow_enqueue(&self, _: DomainId, _: DomainId, _: ObjectId) -> bool { true }
    fn allow_delivery(&self, _: DomainId, _: DomainId, _: ObjectId) -> bool { true }
    fn allow_response(&self, _: DomainId, _: DomainId, _: ObjectId) -> bool { true }
}
struct Deny;
impl TransferPolicy for Deny {
    fn permit(&self, _: DomainId, _: DomainId, _: ObjectId, _: Rights) -> bool { false }
}
impl IpcPolicy for Deny {
    fn allow_enqueue(&self, _: DomainId, _: DomainId, _: ObjectId) -> bool { false }
    fn allow_delivery(&self, _: DomainId, _: DomainId, _: ObjectId) -> bool { false }
    fn allow_response(&self, _: DomainId, _: DomainId, _: ObjectId) -> bool { false }
}

type Table = CapTable<4, 16>;
type Queue = Ipc<2, 16>;
fn setup() -> (
    Table, DomainId, DomainId,
    fortress_cap_ipc::CapHandle, fortress_cap_ipc::CapHandle,
) {
    let server = dom(1, 1);
    let client = dom(2, 1);
    let mut table = Table::new();
    let all = Rights::SEND | Rights::RECEIVE | Rights::REPLY | Rights::TRANSFER;
    let (_, server_cap) = table.bootstrap(server, ObjectKind::Endpoint, all).unwrap();
    let offer = table.prepare_transfer(
        server, server_cap, client, Rights::SEND, Rights::SEND,
    ).unwrap();
    let client_cap = table.commit_transfer(server, offer, &Allow).unwrap();
    (table, server, client, server_cap, client_cap)
}

#[test]
fn legitimate_derive_and_immutable_root() {
    let owner = dom(1, 7);
    let mut table = Table::new();
    let source_rights = Rights::READ | Rights::WRITE | Rights::TRANSFER;
    let (id, root) = table.bootstrap(owner, ObjectKind::Generic, source_rights).unwrap();
    let child = table.derive(owner, root, Rights::READ, Rights::READ).unwrap();
    let info = table.inspect(owner, child).unwrap();
    assert_eq!(info.object, id);
    assert_eq!(info.root.object(), id);
    assert_eq!(info.root.founder(), owner);
    assert_eq!(info.root.original_rights(), source_rights);
    assert_eq!(info.effective(), Rights::READ);
    assert!(table.authorize(owner, child, Rights::READ).is_ok());
    assert_eq!(
        table.authorize(owner, child, Rights::WRITE).unwrap_err(),
        Error::InsufficientRights,
    );
}

#[test]
fn negative_grant_bound_coinflation_reproduces_weak_predicate_only() {
    let a = dom(1, 1);
    let mut table = Table::new();
    let (_, root) = table.bootstrap(a, ObjectKind::Generic, Rights::READ).unwrap();
    let inflated = Rights::READ | Rights::WRITE;
    // The broken legacy predicate accepts both parts if both are inflated.
    assert!(inflated.subset_of(inflated));
    // Canonical immutable root vetoes it, irrespective of mutable bounds.
    assert_eq!(
        table.derive(a, root, inflated, inflated).unwrap_err(),
        Error::Amplification,
    );

    let mut table = Table::new();
    let (_, root) = table.bootstrap(
        a, ObjectKind::Generic, Rights::READ | Rights::WRITE,
    ).unwrap();
    let narrowed = table.derive(
        a, root, Rights::READ | Rights::WRITE, Rights::READ,
    ).unwrap();
    assert_eq!(
        table.derive(a, narrowed, Rights::READ | Rights::WRITE,
            Rights::READ | Rights::WRITE).unwrap_err(),
        Error::Amplification,
    );
}

#[test]
fn negative_provenance_forgery_and_wrong_subject() {
    let a = dom(1, 1);
    let b = dom(2, 1);
    let mut table = Table::new();
    let (_, root) = table.bootstrap(a, ObjectKind::Generic, Rights::READ).unwrap();
    assert_eq!(table.inspect(b, root).unwrap_err(), Error::InvalidHandle);
    let view = table.inspect(a, root).unwrap();
    // A fabricated snapshot is data, never an input accepted as a root mint.
    assert_eq!(view.root.original_rights(), Rights::READ);
    assert!(Rights::WRITE.subset_of(view.root.original_rights()) == false);
    assert!(DomainId::new(1, 0).is_none());
}

#[test]
fn transfer_requires_live_parent_and_explicit_receiver_policy() {
    let a = dom(1, 1);
    let b = dom(2, 1);
    let mut table = Table::new();
    let rights = Rights::READ | Rights::TRANSFER;
    let (_, root) = table.bootstrap(a, ObjectKind::Generic, rights).unwrap();
    let prepared = table.prepare_transfer(a, root, b, Rights::READ, Rights::READ).unwrap();
    assert_eq!(
        table.commit_transfer(a, prepared, &Deny).unwrap_err(), Error::PolicyDenied,
    );
    let remote = table.commit_transfer(a, prepared, &Allow).unwrap();
    assert_eq!(table.inspect(b, remote).unwrap().effective(), Rights::READ);
    assert_eq!(
        table.authorize(b, remote, Rights::WRITE).unwrap_err(),
        Error::InsufficientRights,
    );
    assert_eq!(table.inspect(dom(2, 2), remote).unwrap_err(), Error::InvalidHandle);
}

#[test]
fn transfer_revoke_race_and_cascading_revocation() {
    let a = dom(1, 1);
    let b = dom(2, 1);
    let mut table = Table::new();
    let rights = Rights::READ | Rights::TRANSFER;
    let (_, root) = table.bootstrap(a, ObjectKind::Generic, rights).unwrap();
    let child = table.derive(a, root, rights, rights).unwrap();
    let old = table.prepare_transfer(a, child, b, Rights::READ, Rights::READ).unwrap();
    assert_eq!(table.revoke(a, root).unwrap(), 2);
    assert_eq!(
        table.commit_transfer(a, old, &Allow).unwrap_err(), Error::InvalidHandle,
    );
    assert_eq!(table.revoke(a, root).unwrap_err(), Error::InvalidHandle);
    assert_eq!(table.inspect(a, child).unwrap_err(), Error::InvalidHandle);
}

#[test]
fn object_incarnation_and_handle_generation_prevent_aba() {
    let a = dom(1, 1);
    let mut table: CapTable<1, 2> = CapTable::new();
    let (old_id, old_cap) = table.bootstrap(a, ObjectKind::Generic, Rights::READ).unwrap();
    table.retire_object(old_id).unwrap();
    let (new_id, new_cap) = table.bootstrap(a, ObjectKind::Generic, Rights::READ).unwrap();
    assert_eq!(old_id.slot(), new_id.slot());
    assert_ne!(old_id.incarnation(), new_id.incarnation());
    assert_ne!(old_cap.generation(), new_cap.generation());
    assert_eq!(table.inspect(a, old_cap).unwrap_err(), Error::InvalidHandle);
    assert_eq!(table.retire_object(old_id).unwrap_err(), Error::InvalidObject);
}

#[test]
fn bounds_on_handle_quota_and_missing_transfer_privilege() {
    let a = dom(1, 1);
    let mut table: CapTable<2, 1> = CapTable::new();
    let (_, root) = table.bootstrap(a, ObjectKind::Generic, Rights::READ).unwrap();
    assert_eq!(
        table.derive(a, root, Rights::READ, Rights::READ).unwrap_err(), Error::Full,
    );
    assert_eq!(
        table.prepare_transfer(a, root, dom(2, 1), Rights::READ, Rights::READ)
            .unwrap_err(), Error::InsufficientRights,
    );
}

#[test]
fn positive_bounded_echo_and_duplicate_reply() {
    let (table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    let id = ipc.enqueue(&table, client, client_cap, server, b"hello", 1, 100, &Allow)
        .unwrap();
    assert_eq!(ipc.outstanding(), 1);
    let delivery = ipc.receive(&table, server, server_cap, 2, &Allow).unwrap().unwrap();
    assert_eq!(delivery.id, id);
    assert_eq!(delivery.from, client);
    assert_eq!(delivery.payload(), b"hello");
    ipc.reply(&table, server, server_cap, id, b"HELLO", 3, &Allow).unwrap();
    assert_eq!(
        ipc.reply(&table, server, server_cap, id, b"HELLO", 3, &Allow).unwrap_err(),
        IpcError::DuplicateReply,
    );
    assert_eq!(ipc.collect(&table, client, id, 4, &Allow).unwrap().payload(), b"HELLO");
    assert_eq!(ipc.collect(&table, client, id, 4, &Allow).unwrap_err(), IpcError::NotFound);
    assert_eq!(ipc.outstanding(), 0);
}

#[test]
fn finite_queue_capacity_and_message_limit() {
    let (table, server, client, _server_cap, client_cap) = setup();
    let mut ipc: Ipc<1, 4> = Ipc::new();
    assert_eq!(
        ipc.enqueue(&table, client, client_cap, server, b"oversize", 0, 20, &Allow)
            .unwrap_err(), IpcError::TooLarge,
    );
    let _ = ipc.enqueue(&table, client, client_cap, server, b"abcd", 0, 20, &Allow)
        .unwrap();
    assert_eq!(
        ipc.enqueue(&table, client, client_cap, server, b"x", 1, 20, &Allow)
            .unwrap_err(), IpcError::Full,
    );
}

#[test]
fn cancel_inflight_disallows_late_completion() {
    let (table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    let id = ipc.enqueue(&table, client, client_cap, server, b"x", 0, 100, &Allow)
        .unwrap();
    ipc.receive(&table, server, server_cap, 1, &Allow).unwrap().unwrap();
    ipc.cancel(client, id).unwrap();
    assert_eq!(
        ipc.reply(&table, server, server_cap, id, b"late", 2, &Allow).unwrap_err(),
        IpcError::NotFound,
    );
    assert_eq!(ipc.collect(&table, client, id, 2, &Allow).unwrap_err(), IpcError::NotFound);
    assert_eq!(ipc.cancel(client, id).unwrap_err(), IpcError::NotFound);
}

#[test]
fn expiry_cleans_up_even_inflight_and_prevents_completion() {
    let (table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    assert_eq!(
        ipc.enqueue(&table, client, client_cap, server, b"x", 10, 10, &Allow)
            .unwrap_err(), IpcError::Expired,
    );
    let id = ipc.enqueue(&table, client, client_cap, server, b"x", 10, 12, &Allow)
        .unwrap();
    ipc.receive(&table, server, server_cap, 11, &Allow).unwrap().unwrap();
    assert_eq!(ipc.expire(12), 1);
    assert_eq!(
        ipc.reply(&table, server, server_cap, id, b"x", 12, &Allow).unwrap_err(),
        IpcError::NotFound,
    );
}

#[test]
fn revoked_sender_queued_and_inflight_are_fenced() {
    let (mut table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    let id = ipc.enqueue(&table, client, client_cap, server, b"secret", 0, 100, &Allow)
        .unwrap();
    table.revoke(server, server_cap).unwrap();
    assert_eq!(ipc.reap_invalid(&table), 1);
    assert_eq!(ipc.collect(&table, client, id, 1, &Allow).unwrap_err(), IpcError::NotFound);
    assert_eq!(ipc.receive(&table, server, server_cap, 1, &Allow).unwrap_err(),
        IpcError::Cap(Error::InvalidHandle));
}

#[test]
fn revoke_after_receive_blocks_reply() {
    let (mut table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    let id = ipc.enqueue(&table, client, client_cap, server, b"x", 0, 100, &Allow)
        .unwrap();
    ipc.receive(&table, server, server_cap, 1, &Allow).unwrap().unwrap();
    table.revoke(client, client_cap).unwrap();
    assert_eq!(
        ipc.reply(&table, server, server_cap, id, b"x", 2, &Allow).unwrap_err(),
        IpcError::PolicyDenied,
    );
    assert_eq!(ipc.outstanding(), 0);
}

#[test]
fn receiver_policy_is_rechecked_on_delivery() {
    let (table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    let _ = ipc.enqueue(&table, client, client_cap, server, b"x", 0, 100, &Allow)
        .unwrap();
    assert!(ipc.receive(&table, server, server_cap, 1, &Deny).unwrap().is_none());
    assert_eq!(ipc.outstanding(), 0);
}

#[test]
fn policy_is_rechecked_on_response_and_collection() {
    let (table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    let id = ipc.enqueue(&table, client, client_cap, server, b"x", 0, 100, &Allow)
        .unwrap();
    ipc.receive(&table, server, server_cap, 1, &Allow).unwrap().unwrap();
    assert_eq!(
        ipc.reply(&table, server, server_cap, id, b"x", 2, &Deny).unwrap_err(),
        IpcError::PolicyDenied,
    );
    let id2 = ipc.enqueue(&table, client, client_cap, server, b"x", 3, 100, &Allow)
        .unwrap();
    ipc.receive(&table, server, server_cap, 4, &Allow).unwrap().unwrap();
    ipc.reply(&table, server, server_cap, id2, b"x", 5, &Allow).unwrap();
    assert_eq!(
        ipc.collect(&table, client, id2, 6, &Deny).unwrap_err(), IpcError::PolicyDenied,
    );
}

#[test]
fn stale_process_incarnation_cannot_take_reply_or_cancel() {
    let (table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    let id = ipc.enqueue(&table, client, client_cap, server, b"x", 0, 100, &Allow)
        .unwrap();
    ipc.receive(&table, server, server_cap, 1, &Allow).unwrap().unwrap();
    ipc.reply(&table, server, server_cap, id, b"y", 2, &Allow).unwrap();
    let restarted = dom(client.slot(), client.incarnation() + 1);
    assert_eq!(ipc.cancel(restarted, id).unwrap_err(), IpcError::WrongPeer);
    assert_eq!(
        ipc.collect(&table, restarted, id, 3, &Allow).unwrap_err(), IpcError::WrongPeer,
    );
    assert_eq!(ipc.collect(&table, client, id, 3, &Allow).unwrap().payload(), b"y");
}

#[test]
fn unauthorized_send_and_wrong_endpoint_receiver() {
    let (table, server, client, server_cap, client_cap) = setup();
    let mut ipc = Queue::new();
    assert_eq!(
        ipc.enqueue(&table, server, server_cap, client, b"x", 0, 100, &Allow)
            .unwrap_err(), IpcError::WrongPeer,
    );
    assert_eq!(
        ipc.enqueue(&table, client, client_cap, server, b"x", 0, 100, &Deny)
            .unwrap_err(), IpcError::PolicyDenied,
    );
    assert_eq!(
        ipc.receive(&table, client, client_cap, 1, &Allow).unwrap_err(),
        IpcError::Cap(Error::InsufficientRights),
    );
}
