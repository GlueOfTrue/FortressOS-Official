//! Construct the fixture PMM from the already validated Limine boot map.
use fortress_memory_model::{
    k1_frames::{BootExtent, Error, FramePool, ReservedSpan, LIMINE_USABLE},
    FRAME_SIZE,
};

use crate::bootinfo::BootInfoV0;

const MAX_FIXTURE_REGIONS: usize = 64;
const LIMINE_RESERVED: u64 = 1;

pub fn frame_pool<const LIVE: usize>(
    info: &BootInfoV0,
) -> Result<FramePool<MAX_FIXTURE_REGIONS, LIVE>, Error> {
    let regions = info.region_slice();
    if regions.len() > MAX_FIXTURE_REGIONS {
        return Err(Error::RegionCapacity);
    }
    // The loader may mark [0, N) usable. Reserve physical page zero even
    // under that map. Preserve all other intervals for the PMM's checks.
    let mut extents = [BootExtent { base: 0, length: 0, kind: LIMINE_RESERVED };
        MAX_FIXTURE_REGIONS + 1];
    let mut count = 0;
    for region in regions {
        let mut extent = BootExtent {
            base: region.base,
            length: region.length,
            kind: region.kind,
        };
        if count == 0 && extent.base == 0 && extent.kind == LIMINE_USABLE {
            if extent.length < FRAME_SIZE || extent.length % FRAME_SIZE != 0 {
                return Err(Error::Unaligned);
            }
            extents[count] = BootExtent { base: 0, length: FRAME_SIZE, kind: LIMINE_RESERVED };
            count += 1;
            extent.base += FRAME_SIZE;
            extent.length -= FRAME_SIZE;
            if extent.length == 0 {
                continue;
            }
        }
        extents[count] = extent;
        count += 1;
    }
    let protected = [ReservedSpan {
        base: info.kernel_physical_base,
        length: info.kernel_size,
    }];
    FramePool::from_validated_boot(&extents[..count], &protected)
}
