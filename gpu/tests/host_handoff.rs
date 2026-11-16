//! Host-only contract test for the GPU, MEMORY and ARCH models.

use fortress_arch_irq::{DeviceKey, IrqError, IrqTable, Retire, FIRST_DEVICE_VECTOR};
use fortress_gpu::{BarKind, BarLease, BarRegistry, Error as GpuError, MemoryBar, PciAddress, PciIdentity};
use fortress_memory_model::mmio::{BarGrant, CacheMode, MmioError};
use fortress_memory_model::FRAME_SIZE;

fn grant_from_live_bar(registry: &BarRegistry<2>, lease: BarLease, device: DeviceKey) -> BarGrant {
    let range = registry.inspect(lease).unwrap().range();
    BarGrant::from_inventory(
        device.id,
        device.incarnation,
        range.base(),
        range.end() - range.base(),
        CacheMode::Uncached,
    )
    .unwrap()
}

#[test]
fn validates_mmio_and_drains_irq_before_bar_reuse() {
    let pci = PciIdentity {
        address: PciAddress::new(0, 1, 0, 0).unwrap(),
        vendor_id: 0x1af4,
        device_id: 0x1050,
        class: 3,
        subclass: 0,
        incarnation: 1,
    };
    // A simulated inventory assigns the device ID and cache mode.
    let device = DeviceKey {
        id: 17,
        incarnation: pci.incarnation,
    };
    let base = 0x9000_0000;
    let size = 2 * FRAME_SIZE;
    let bar = MemoryBar::from_inventory(0, BarKind::Memory64, base, size).unwrap();
    let mut bars = BarRegistry::<2>::new();
    let bar_lease = bars.claim(pci, Some(bar), &[]).unwrap();
    let grant = grant_from_live_bar(&bars, bar_lease, device);

    let start = base + 0x123;
    let mapped = grant
        .validate(device.id, device.incarnation, start, 71, CacheMode::Uncached, false)
        .unwrap();
    assert_eq!((mapped.request_start, mapped.request_end), (start, start + 71));
    assert_eq!((mapped.page_start, mapped.page_end), (base, base + FRAME_SIZE));
    assert_eq!(
        grant.validate(device.id, device.incarnation, base + size - 1, 2, CacheMode::Uncached, false),
        Err(MmioError::OutsideBar),
    );

    let mut irqs = IrqTable::new();
    let irq = irqs.register(FIRST_DEVICE_VECTOR, device).unwrap();
    irqs.unmask(irq).unwrap();
    let ticket = irqs.deliver(irq).unwrap();
    assert_eq!(irqs.unregister(irq), Ok(Retire::DeferredUntilAck));
    irqs.finish_handler(ticket).unwrap();

    let next_pci = PciIdentity { incarnation: 2, ..pci };
    let next_device = DeviceKey { incarnation: next_pci.incarnation, ..device };
    // The host broker keeps BAR ownership while the old IRQ awaits acknowledgment.
    assert_eq!(
        irqs.register(FIRST_DEVICE_VECTOR, next_device),
        Err(IrqError::AlreadyRegistered),
    );
    // The same BDF/BAR stays occupied even if a reprobe reports a new range.
    let reprobed_bar = MemoryBar::from_inventory(0, BarKind::Memory64, base + size, size).unwrap();
    assert_eq!(
        bars.claim(next_pci, Some(reprobed_bar), &[]),
        Err(GpuError::ResourceConflict),
    );
    irqs.acknowledge(ticket).unwrap();
    bars.release(bar_lease).unwrap();

    let next_bar = bars.claim(next_pci, Some(bar), &[]).unwrap();
    let next_grant = grant_from_live_bar(&bars, next_bar, next_device);
    let next_irq = irqs.register(FIRST_DEVICE_VECTOR, next_device).unwrap();
    assert_eq!(bars.inspect(bar_lease), Err(GpuError::StaleLease));
    assert_eq!(irqs.acknowledge(ticket), Err(IrqError::StaleLease));
    assert_eq!(
        next_grant.validate(device.id, device.incarnation, start, 71, CacheMode::Uncached, false),
        Err(MmioError::WrongDevice),
    );
    assert!(next_grant
        .validate(next_device.id, next_device.incarnation, start, 71, CacheMode::Uncached, false)
        .is_ok());
    irqs.unmask(next_irq).unwrap();
}
