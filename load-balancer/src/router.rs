use internet_checksum::update;
use load_balancer_common::MIN_IPV4_HEADER_LEN;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

/// Get mutable headers from the raw packet data. This function is used to extract the Ethernet, IPv4, and TCP headers.
#[inline(always)]
pub fn get_mut_headers(frame_data: &mut [u8]) -> Option<(&mut EthHdr, &mut Ipv4Hdr, &mut TcpHdr)> {
    let eth_hdr = unsafe { &mut *(frame_data.as_mut_ptr() as *mut EthHdr) };
    let ether_type = eth_hdr.ether_type;

    if ether_type != network_types::eth::EtherType::Ipv4 {
        return None;
    }

    let ipv4_hdr = unsafe { &mut *(frame_data.as_mut_ptr().add(EthHdr::LEN) as *mut Ipv4Hdr) };

    if ipv4_hdr.proto != network_types::ip::IpProto::Tcp {
        return None;
    }

    let tcp_hdr_offset = if ipv4_hdr.ihl() == 5 {
        EthHdr::LEN + MIN_IPV4_HEADER_LEN
    } else {
        EthHdr::LEN + (ipv4_hdr.ihl() as usize) * 4
    };

    let tcp_hdr = unsafe { &mut *(frame_data.as_mut_ptr().add(tcp_hdr_offset) as *mut TcpHdr) };

    Some((eth_hdr, ipv4_hdr, tcp_hdr))
}

/// Shift the source and destination MAC addresses in the Ethernet header of the packet. This is necessary to redirect the packet,
/// if we don't, the kernel will drop the packet because it will think that the packet is coming from internet and not going back to it.
#[inline(always)]
pub fn shift_mac(eth_hdr: &mut EthHdr) {
    let src_mac = eth_hdr.src_addr;
    let dst_mac = eth_hdr.dst_addr;

    eth_hdr.src_addr = dst_mac;
    eth_hdr.dst_addr = src_mac;
}

// To implement checksum update I'm using internet-checksum. This crate is optimized to calculate checksums efficiently and take advantage of CPU.
// You can check the code on the following link https://docs.rs/internet-checksum/0.2.1/src/internet_checksum/lib.rs.html
/// Route the packet by modifying the destination IP address and port in the IPv4 and TCP headers, respectively. It also updates the checksums accordingly.
/// port_dest and port_origin should be in big endian.
#[inline(always)]
pub fn route_packet(
    ipv4_hdr: &mut Ipv4Hdr,
    tcp_hdr: &mut TcpHdr,
    ip_dest: [u8; 4],
    port_dest: u16,
    port_origin: u16,
) {
    let old_dst_ip = ipv4_hdr.dst_addr;
    let old_src_ip = ipv4_hdr.src_addr;
    let old_csum_ip = ipv4_hdr.check;

    ipv4_hdr.src_addr = old_dst_ip;
    ipv4_hdr.dst_addr = ip_dest;

    ipv4_hdr.check = update(old_csum_ip, &old_src_ip, &ip_dest);

    let old_dst_port = tcp_hdr.dest;
    let old_source_port = tcp_hdr.source;
    let mut old_csum_tcp_bytes = tcp_hdr.check.to_be_bytes();

    tcp_hdr.source = port_origin;
    tcp_hdr.dest = port_dest;

    old_csum_tcp_bytes = update(
        old_csum_tcp_bytes,
        &old_dst_port.to_be_bytes(),
        &port_dest.to_be_bytes(),
    );

    old_csum_tcp_bytes = update(
        old_csum_tcp_bytes,
        &old_source_port.to_be_bytes(),
        &port_origin.to_be_bytes(),
    );

    old_csum_tcp_bytes = update(old_csum_tcp_bytes, &old_src_ip, &ip_dest);

    // I'm using here from_ne_bytes because update function expects values in native endianess.
    tcp_hdr.check = u16::from_ne_bytes(old_csum_tcp_bytes);
}
