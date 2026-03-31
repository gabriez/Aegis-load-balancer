#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{xdp::XskMap, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use load_balancer_common::{MAX_BLOCKLIST_ENTRIES, MIN_IPV4_HEADER_LEN};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr, // tcp::TcpHdr,
                 // udp::UdpHdr,
};

#[map(name = "XSK_SOCKS")]
static XSK_SOCKS: XskMap = XskMap::with_max_entries(12, 0);

// We are using a hashmap to store the blocklist of IP addresses. The key is the source IP address and the value is a
// boolean indicating whether to drop the packet or not. I decided to use this instead of an array because we can easily add and remove IP addresses from the blocklist
// without having to worry about the size of the array. The value is a u64 that counts the number of times the IP address has been blocked,
// which can be useful for monitoring and debugging purposes.
#[map(name = "BLOCKLIST")]
static BLOCKLIST: HashMap<[u8; 4], u64> = HashMap::with_max_entries(MAX_BLOCKLIST_ENTRIES, 0);

// TODO: study the implementation of a bloom filter for blocking IP addresses in the future.

#[xdp]
pub fn load_balancer(ctx: XdpContext) -> u32 {
    match try_load_balancer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_load_balancer(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    // Check if the source IP address is in the blocklist. If it is, drop the packet.
    if let Some(blocked) = unsafe { BLOCKLIST.get_ptr_mut(&(*ipv4hdr).src_addr) } {
        blocked.wrapping_add(1);

        return Ok(xdp_action::XDP_DROP);
    }

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let ipv4_ihl = unsafe { (*ipv4hdr).ihl() };

            let ipv4hdr_len: usize = if ipv4_ihl == 5 {
                EthHdr::LEN + MIN_IPV4_HEADER_LEN
            } else {
                EthHdr::LEN + (ipv4_ihl as usize) * 4
            };

            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + ipv4hdr_len)?;
            let port = unsafe { u16::from_be((*tcphdr).source) };

            let flag_psh = unsafe { (*tcphdr).psh() };
            let flag_syn = unsafe { (*tcphdr).syn() };
            let flag_ack = unsafe { (*tcphdr).ack() };
            let flag_ece = unsafe { (*tcphdr).ece() };
            let flag_fin = unsafe { (*tcphdr).fin() };
            let flag_cwr = unsafe { (*tcphdr).cwr() };

            info!(
                &ctx,
                "port src: {}
            psh flag: {} \n 
            syn flag: {} \n 
            ack flag: {} \n 
            flag_ece: {} \n 
            flag_fin: {} \n 
            flag_cwr: {} \n",
                port,
                flag_psh,
                flag_syn,
                flag_ack,
                flag_ece,
                flag_fin,
                flag_cwr
            );

            if port == 1299 {
                let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
                let code_value = XSK_SOCKS
                    .redirect(queue_id, 0)
                    .unwrap_or(xdp_action::XDP_ABORTED);
                return Ok(code_value);
            }
            return Ok(xdp_action::XDP_PASS);
        }
        IpProto::Udp => Ok(xdp_action::XDP_PASS),
        _ => Err(()),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
