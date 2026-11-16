//! DMA lease controller requiring actual IOMMU and CPU/device barriers.
//! Trust boundary: implementation of DmaHardware is privileged and MUST verify
//! the IOMMU translation was installed/invalidated on the actual device, and
//! that PCI bus mastering cannot escape the domain. Fake hardware = host tests.
//! No direct physical DMA or permissive fallback when the IOMMU is absent.

use crate::lifetime::{Ledger, FrameToken, DmaToken, Fault};

pub trait DmaHardware {
    /// Some(domain) only after DMAR/VT-d discovery, DMA-remap enable, device
    /// source-ID attachment, and verified isolation. NOT a user-provided ID.
    fn verified_domain(&self, device: u64) -> Option<u64>;
    /// PCI Bus Mastering must be disabled before changing any IOMMU mapping.
    fn bus_mastering_disabled(&self, device: u64) -> bool;
    /// Must write page tables and guarantee translated IOVA, no identity bypass.
    fn install_mapping(&mut self, domain: u64, device: u64, iova: u64,
                       physical: u64, length: u64) -> Result<(), ()>;
    fn start_dma(&mut self, device: u64) -> Result<(), ()>;
    /// Stop bus mastering, quiesce queues and drain any outstanding transactions.
    fn stop_and_drain(&mut self, device: u64) -> Result<(), ()>;
    fn remove_mapping(&mut self, domain: u64, iova: u64,
                      length: u64) -> Result<(), ()>;
    /// Must synchronously acknowledge IOTLB/queued invalidation for device.
    fn invalidate_iotlb_sync(&mut self, domain: u64, device: u64) -> Result<(), ()>;
    /// Must synchronously shoot down ALL specified CPUs/PCIDs as necessary.
    fn invalidate_cpu_sync(&mut self, cpu_mask: u64) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Ledger(Fault), NoIommu, InvalidGeometry, HardwareFailed, Stale, Busy,
}
#[derive(Clone, Copy)]
pub struct Lease {
    token: DmaToken,
    frame: FrameToken,
    device: u64,
    domain: u64,
    iova: u64,
    cpu_mask: u64,
}
pub struct DmaController<'a, H: DmaHardware, const P: usize,
                         const M: usize, const D: usize> {
    pub ledger: &'a mut Ledger<P,M,D>,
    hw: H,
}
impl<'a,H:DmaHardware,const P:usize,const M:usize,const D:usize>
    DmaController<'a,H,P,M,D> {
    pub fn new(ledger: &'a mut Ledger<P,M,D>, hw: H) -> Self {
        Self { ledger, hw }
    }
    pub fn attach_page(&mut self, frame: FrameToken, owner: u64,
                       device: u64, cpu_mask: u64, iova: u64)
        -> Result<Lease,Error> {
        if iova == 0 || iova % crate::FRAME_SIZE != 0 || cpu_mask == 0 {
            return Err(Error::InvalidGeometry);
        }
        if !self.hw.bus_mastering_disabled(device) {return Err(Error::HardwareFailed);}
        let domain = self.hw.verified_domain(device).ok_or(Error::NoIommu)?;
        if domain == 0 { return Err(Error::NoIommu); }
        let token = self.ledger.pin_dma(frame,owner,device,cpu_mask)
            .map_err(Error::Ledger)?;
        let physical=self.ledger.address(frame).map_err(Error::Ledger)?;
        // If mapping fails partway, its PTEs could remain resident.
        // Even without active bus mastering, preserve/quarantine the frame.
        if self.hw.install_mapping(domain,device,iova,physical,crate::FRAME_SIZE).is_err() ||
           self.hw.invalidate_iotlb_sync(domain,device).is_err() {
            let _ = self.ledger.quarantine_dma(token);
            return Err(Error::HardwareFailed);
        }
        if self.ledger.map_dma(token,Some(domain)).is_err() {
            let _=self.ledger.quarantine_dma(token);
            return Err(Error::HardwareFailed);
        }
        Ok(Lease {token,frame,device,domain,iova,cpu_mask})
    }
    pub fn submit(&mut self, lease: Lease) -> Result<(),Error> {
        if self.hw.verified_domain(lease.device) != Some(lease.domain) {
            let _=self.ledger.quarantine_dma(lease.token);
            return Err(Error::NoIommu);
        }
        self.ledger.submit_dma(lease.token).map_err(Error::Ledger)?;
        if self.hw.start_dma(lease.device).is_err() {
            let _=self.ledger.quarantine_dma(lease.token);
            return Err(Error::HardwareFailed);
        }
        Ok(())
    }
    /// If hardware stop, IOTLB or CPU invalidation fails, the frame is never
    /// automatically unpinned or retyped; this is a deliberate resource leak.
    pub fn revoke(&mut self, lease: Lease, owner: u64) -> Result<(),Error> {
        self.ledger.begin_dma_revoke(lease.token,owner)
            .map_err(Error::Ledger)?;
        if self.hw.stop_and_drain(lease.device).is_err() {
            let _=self.ledger.quarantine_dma(lease.token);
            return Err(Error::HardwareFailed);
        }
        self.ledger.ack_device_stopped(lease.token).map_err(Error::Ledger)?;
        if self.hw.remove_mapping(lease.domain,lease.iova,crate::FRAME_SIZE).is_err() ||
           self.hw.invalidate_iotlb_sync(lease.domain,lease.device).is_err() {
            let _=self.ledger.quarantine_dma(lease.token);
            return Err(Error::HardwareFailed);
        }
        self.ledger.ack_iommu(lease.token).map_err(Error::Ledger)?;
        if self.hw.invalidate_cpu_sync(lease.cpu_mask).is_err() {
            let _=self.ledger.quarantine_dma(lease.token);
            return Err(Error::HardwareFailed);
        }
        for cpu in 0..64 {
            if lease.cpu_mask & (1u64<<cpu) != 0 {
                self.ledger.ack_dma_cpu(lease.token,cpu as u8)
                    .map_err(Error::Ledger)?;
            }
        }
        self.ledger.finish_dma_revoke(lease.token,owner).map_err(Error::Ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifetime::{PageClass,DmaPhase};
    type L=Ledger<8,4,4>;
    struct Mock { has_iommu: bool, fail: u8, active: bool,
                  mapped: bool, invalidate_count: u8 }
    impl Mock {
        fn normal()->Self{Self{has_iommu:true,fail:0,active:false,mapped:false,invalidate_count:0}}
    }
    impl DmaHardware for Mock {
        fn verified_domain(&self,_:u64)->Option<u64>{
            if self.has_iommu {Some(5)} else {None}
        }
        fn bus_mastering_disabled(&self,_:u64)->bool{!self.active}
        fn install_mapping(&mut self,_:u64,_:u64,_:u64,_:u64,_:u64)->Result<(),()>{
            if self.fail==1 { return Err(()); }
            self.mapped=true;Ok(())
        }
        fn start_dma(&mut self,_:u64)->Result<(),()>{
            if !self.mapped||self.fail==2{return Err(());}
            self.active=true;Ok(())
        }
        fn stop_and_drain(&mut self,_:u64)->Result<(),()>{
            if self.fail==3{return Err(());}
            self.active=false;Ok(())
        }
        fn remove_mapping(&mut self,_:u64,_:u64,_:u64)->Result<(),()>{
            if self.active||self.fail==4{return Err(());}
            self.mapped=false;Ok(())
        }
        fn invalidate_iotlb_sync(&mut self,_:u64,_:u64)->Result<(),()>{
            self.invalidate_count+=1;
            if self.fail==5 && self.invalidate_count==2{return Err(());}
            Ok(())
        }
        fn invalidate_cpu_sync(&mut self,_:u64)->Result<(),()>{
            if self.fail==6{return Err(());}
            Ok(())
        }
    }
    fn one()->(L,FrameToken){
        let mut l=L::new();
        l.register_page(0x1000,PageClass::Free).unwrap();
        l.seal().unwrap();
        let f=l.allocate(7).unwrap();
        (l,f)
    }
    #[test] fn lifecycle_retires_only_after_iotlb_and_cpu() {
        let (mut ledger,f)=one();
        let mut m=DmaController::new(&mut ledger,Mock::normal());
        let d=m.attach_page(f,7,22,0b11,0x8000).unwrap();
        assert_eq!(m.ledger.free(f,7),Err(Fault::Busy));
        m.submit(d).unwrap();
        m.revoke(d,7).unwrap();
        assert_eq!(m.ledger.dma_phase(d.token),Err(Fault::Stale));
        m.ledger.free(f,7).unwrap();
        assert_eq!(m.hw.invalidate_count,2);
    }
    #[test] fn absent_iommu_is_strictly_denied() {
        let (mut ledger,f)=one();
        let mut hw=Mock::normal();hw.has_iommu=false;
        let mut m=DmaController::new(&mut ledger,hw);
        assert!(matches!(m.attach_page(f,7,22,1,0x8000),Err(Error::NoIommu)));
        m.ledger.free(f,7).unwrap();
    }
    #[test] fn partial_iommu_map_failure_quarantines_frame() {
        let (mut ledger,f)=one();
        let mut hw=Mock::normal();hw.fail=1;
        let mut m=DmaController::new(&mut ledger,hw);
        assert!(matches!(m.attach_page(f,7,22,1,0x8000),Err(Error::HardwareFailed)));
        assert_eq!(m.ledger.free(f,7),Err(Fault::Busy));
    }
    #[test] fn drain_failure_quarantines_after_submit() {
        let (mut ledger,f)=one();
        let mut m=DmaController::new(&mut ledger,Mock::normal());
        let d=m.attach_page(f,7,22,1,0x8000).unwrap();
        m.submit(d).unwrap();
        m.hw.fail=3;
        assert!(matches!(m.revoke(d,7),Err(Error::HardwareFailed)));
        assert_eq!(m.ledger.dma_phase(d.token),Ok(DmaPhase::Quarantined));
        assert_eq!(m.ledger.free(f,7),Err(Fault::Busy));
    }
    #[test] fn missing_iotlb_or_cpu_ack_quarantines() {
        for fail in [5,6] {
            let (mut ledger,f)=one();
            let mut m=DmaController::new(&mut ledger,Mock::normal());
            let d=m.attach_page(f,7,22,1,0x8000).unwrap();
            m.submit(d).unwrap();
            m.hw.fail=fail;
            assert!(matches!(m.revoke(d,7),Err(Error::HardwareFailed)));
            assert_eq!(m.ledger.free(f,7),Err(Fault::Busy));
        }
    }
}
