use agave_afxdp::{
    device::{RxFillRing, TxCompletionRing},
    socket::{RingFull, TxRing},
    tx_loop::kick,
    umem::{Frame, SliceUmem, SliceUmemFrame, Umem},
};
use log::warn;
use thiserror::Error;

use crate::{
    connections_manager::RouteAddress,
    router::{get_mut_headers, route_packet, shift_mac},
};

pub const FRAME_COUNT: usize = 4096;
pub const PACKETS_BATCH: usize = 64;

#[derive(Error, Debug)]
pub enum FramesError {
    #[error("No space available to insert frame")]
    NoSpace,
}
pub struct FramesManager<'a> {
    max_frames: usize,
    pub frame_available: usize,
    frames: Vec<Option<SliceUmemFrame<'a>>>,
}

impl<'a> FramesManager<'a> {
    pub fn new() -> Self {
        let mut frames = Vec::with_capacity(FRAME_COUNT);
        for _ in 0..FRAME_COUNT {
            frames.push(None);
        }
        FramesManager {
            max_frames: FRAME_COUNT,
            frame_available: 0,
            frames,
        }
    }

    pub fn build_with_capacity(capacity: usize) -> Self {
        let mut frames = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            frames.push(None);
        }
        FramesManager {
            max_frames: capacity,
            frame_available: 0,
            frames,
        }
    }

    #[inline(always)]
    pub fn insert_frame(&mut self, frame: SliceUmemFrame<'a>) -> Result<(), FramesError> {
        if self.frame_available < self.max_frames {
            self.frames[self.frame_available] = Some(frame);
            self.frame_available += 1;
            Ok(())
        } else {
            Err(FramesError::NoSpace)
        }
    }

    #[inline(always)]
    pub fn get_free_frame(&mut self) -> Option<SliceUmemFrame<'a>> {
        if self.frame_available > 0 {
            self.frame_available -= 1;
            self.frames[self.frame_available].take()
        } else {
            None
        }
    }

    pub fn insert_frames_from_umem(
        &mut self,
        umem: &mut impl Umem<Frame = SliceUmemFrame<'a>>,
    ) -> Result<(), FramesError> {
        while let Some(frame) = umem.reserve() {
            self.insert_frame(frame)?;
        }
        Ok(())
    }
}

impl Default for FramesManager<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Iterator for FramesManager<'a> {
    type Item = SliceUmemFrame<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.get_free_frame()
    }
}

type PacketsBatch<'a> = [Option<SliceUmemFrame<'a>>; PACKETS_BATCH];

#[inline(always)]
pub fn receive_packets<'a>(
    batch_size: usize,
    rx_ring: &mut agave_afxdp::socket::RxRing,
) -> PacketsBatch<'a> {
    let mut packets: PacketsBatch = [const { None }; PACKETS_BATCH];
    let mut received = 0;

    // TODO: insert statistic for packets received and bytes received
    while received < batch_size {
        if let Some(packet) = rx_ring.read() {
            packets[received] = Some(SliceUmemFrame::from(packet));
            received += 1;
        } else {
            break;
        }
    }

    packets
}

#[inline(always)]
pub fn process_packets<'a>(
    // address_provider: &impl AddressProvider,
    mut received: PacketsBatch<'a>,
    umem: &mut SliceUmem<'a>,
    address_provider: &impl RouteAddress,
) -> PacketsBatch<'a> {
    let mut routed: PacketsBatch = [const { None }; PACKETS_BATCH];

    for (index, packet) in received.iter_mut().enumerate() {
        if let Some(frame) = packet.take() {
            let frame_data = umem.map_frame_mut(&frame);

            if let Some((eth_hdr, ipv4_hdr, tcp_hdr)) = get_mut_headers(frame_data) {
                if let Some(redirection_address) =
                    address_provider.get_redirection_addr(ipv4_hdr, tcp_hdr)
                {
                    shift_mac(eth_hdr);
                    route_packet(
                        ipv4_hdr,
                        tcp_hdr,
                        redirection_address.dest_ip,
                        redirection_address.dest_port,
                        redirection_address.origin_port,
                    );
                    routed[index] = Some(frame);
                    continue;
                }
            }
            // TODO: Implement statistic for packets dropped and bytes dropped

            umem.release(frame.offset());
        } else {
            // We allow to break the loop when we find the first None packet because receive_packets fills the array sequentially
            break;
        }
    }

    routed
}

#[inline(always)]
pub fn send_packets<'a>(
    tx_ring: &mut TxRing<SliceUmemFrame<'a>>,
    routed: PacketsBatch<'a>,
    umem: &mut SliceUmem<'a>,
) {
    let mut packets_written = 0;
    for packet in routed {
        if let Some(frame) = packet {
            match tx_ring.write(frame, 0) {
                Ok(_) => {
                    packets_written += 1;
                }
                //TODO: Should we retry send here or maybe kicking the tx_ring again?
                Err(RingFull(frame_ret)) => {
                    umem.release(frame_ret.offset());
                }
            }
        } else {
            break;
        }
    }

    // TODO: implement statistics for packets forwarded and bytes sent
    if packets_written > 0 {
        tx_ring.commit();

        kick(tx_ring);
    }
}

#[inline(always)]
pub fn free_tx_frames(batch_size: usize, tx_ring: &mut TxRing<SliceUmemFrame<'_>>) -> usize {
    let available_tx = tx_ring.available();
    if available_tx < batch_size {
        tx_ring.commit();
        kick(tx_ring);
        tx_ring.sync(false);

        let available_tx_after = tx_ring.available();

        if available_tx_after < batch_size {
            return available_tx_after;
        }
    }
    batch_size
}

#[inline(always)]
pub fn release_cq_frames(umem: &mut SliceUmem<'_>, completion_ring: &mut TxCompletionRing) {
    completion_ring.sync(false);
    while let Some(completed_frame) = completion_ring.read() {
        umem.release(completed_frame);
    }
    completion_ring.commit();
}

#[inline(always)]
pub fn recycle_frames<'a>(
    umem: &mut SliceUmem<'a>,
    fill_ring: &mut agave_afxdp::device::RxFillRing<SliceUmemFrame<'a>>,
    frames_manager: &mut FramesManager<'a>,
) -> anyhow::Result<()> {
    let available_frames = umem.available();
    fill_ring.sync(false);

    if available_frames > 0 {
        if let Err(err) = frames_manager.insert_frames_from_umem(umem) {
            warn!("Failed to insert frames from umem: {}", err);
        }

        insert_frames_fill_ring(fill_ring, frames_manager);

        if fill_ring.needs_wakeup() {
            fill_ring.wake()?;
        }
        fill_ring.sync(false);
    }

    Ok(())
}

#[inline(always)]
pub fn insert_frames_fill_ring<'a>(
    fill_ring: &mut RxFillRing<SliceUmemFrame<'a>>,
    frames_manager: &mut FramesManager<'a>,
) {
    while let Some(frame) = frames_manager.get_free_frame() {
        if let Err((frame_ret, err)) = fill_ring.write(frame) {
            warn!(
                "Failed to write frame to fill ring: {}. Returning frame",
                err
            );
            frames_manager
                .insert_frame(frame_ret)
                .expect("Failed to return frame to manager");
            break;
        }
    }

    fill_ring.commit();
}
