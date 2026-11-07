use internet_checksum::{checksum, update};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

/// Get mutable headers from the raw packet data. This function is used to extract the Ethernet, IPv4, and TCP headers.
///
/// TODO: create checks to validate TCP package length. Maybe I could do it before getting to this function
#[inline(always)]
pub fn get_mut_headers<'a>(
    frame_data: &'a mut [u8],
) -> Option<(&'a mut EthHdr, &'a mut Ipv4Hdr, &'a mut TcpHdr, &'a [u8])> {
    let eth_hdr = unsafe { &mut *(frame_data.as_mut_ptr() as *mut EthHdr) };
    let ether_type = eth_hdr.ether_type;

    if ether_type != network_types::eth::EtherType::Ipv4 {
        return None;
    }

    let ipv4_hdr = unsafe { &mut *(frame_data.as_mut_ptr().add(EthHdr::LEN) as *mut Ipv4Hdr) };

    if ipv4_hdr.proto != network_types::ip::IpProto::Tcp {
        return None;
    }

    let tcp_hdr_offset = EthHdr::LEN + (ipv4_hdr.ihl() as usize) * 4;

    let tcp_hdr = unsafe { &mut *(frame_data.as_mut_ptr().add(tcp_hdr_offset) as *mut TcpHdr) };

    // WARNING: this is a raw pointer to the TCP payload, it should be used with caution and only for reading, modifying the payload can cause undefined behavior if not done correctly.
    // we are bypassing the safety checks of Rust, so we need to be careful when using this pointer. We are using it to calculate the TCP checksum, which requires access to the TCP payload.
    let raw_tcp_hdr: &'a [u8] = &frame_data[tcp_hdr_offset..];

    Some((eth_hdr, ipv4_hdr, tcp_hdr, raw_tcp_hdr))
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

    ipv4_hdr.src_addr = old_dst_ip;
    ipv4_hdr.dst_addr = ip_dest;

    tcp_hdr.source = port_origin;
    tcp_hdr.dest = port_dest;
}

#[inline(always)]
pub fn calculate_tcp_csum<'a>(tcp_hdr: &mut TcpHdr, ipv4_hdr: &Ipv4Hdr, raw_tcp_hdr: &'a [u8]) {
    let src_ip = ipv4_hdr.src_addr;
    let dst_ip = ipv4_hdr.dst_addr;
    let protocol = 6; // TCP uses number 6
    let tcp_len = ipv4_hdr.total_len() - (ipv4_hdr.ihl() as u16 * 4);
    let padding = 0u8;

    let pseudo_header = [
        src_ip[0],
        src_ip[1],
        src_ip[2],
        src_ip[3],
        dst_ip[0],
        dst_ip[1],
        dst_ip[2],
        dst_ip[3],
        padding,
        protocol,
        (tcp_len >> 8) as u8,
        (tcp_len & 0xFF) as u8,
    ];

    let tcp_bf_csum = &raw_tcp_hdr[..16];
    let tcp_af_csum = &raw_tcp_hdr[18..];
    let csum_zeroed: [u8; 2] = [0, 0];

    let csum_data = [&pseudo_header[..], tcp_bf_csum, &csum_zeroed, tcp_af_csum].concat();

    tcp_hdr.check = u16::from_ne_bytes(checksum(&csum_data)).to_be();
}

#[inline(always)]
pub fn update_tcp_csum(
    ipv4_hdr: &mut Ipv4Hdr,
    tcp_hdr: &mut TcpHdr,
    ip_dest: [u8; 4],
    port_dest: u16,
    port_origin: u16,
) {
    let old_src_ip = ipv4_hdr.src_addr;
    let old_csum_ip = ipv4_hdr.check;

    ipv4_hdr.check = update(old_csum_ip, &old_src_ip, &ip_dest);

    let old_dst_port = tcp_hdr.dest;
    let old_source_port = tcp_hdr.source;

    let mut old_csum_tcp_bytes = u16::from_be(tcp_hdr.check).to_ne_bytes();

    old_csum_tcp_bytes = update(
        old_csum_tcp_bytes,
        &old_dst_port.to_ne_bytes(),
        &port_dest.to_ne_bytes(),
    );

    old_csum_tcp_bytes = update(
        old_csum_tcp_bytes,
        &old_source_port.to_ne_bytes(),
        &port_origin.to_ne_bytes(),
    );

    old_csum_tcp_bytes = update(old_csum_tcp_bytes, &old_src_ip, &ip_dest);

    let csum = u16::from_ne_bytes(old_csum_tcp_bytes);

    tcp_hdr.check = csum;
}
