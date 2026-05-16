use std::fmt;

use network_types::{bitfield::BitfieldUnit, tcp::TcpHdr};
use thiserror::Error;

pub mod config;
pub mod connections_balancer;
pub mod connections_manager;
pub mod pipeline;
pub mod router;

// The TCP flags.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod TcpFlags {
    /// CWR – Congestion Window Reduced (CWR) flag is set by the sending
    /// host to indicate that it received a TCP segment with the ECE flag set
    /// and had responded in congestion control mechanism (added to header by RFC 3168).
    pub const CWR: u8 = 0b10000000;
    /// ECE – ECN-Echo has a dual role, depending on the value of the
    /// SYN flag. It indicates:
    /// If the SYN flag is set (1), that the TCP peer is ECN capable.
    /// If the SYN flag is clear (0), that a packet with Congestion Experienced
    /// flag set (ECN=11) in IP header received during normal transmission
    /// (added to header by RFC 3168).
    pub const ECE: u8 = 0b01000000;
    /// URG – indicates that the Urgent pointer field is significant.
    pub const URG: u8 = 0b00100000;
    /// ACK – indicates that the Acknowledgment field is significant.
    /// All packets after the initial SYN packet sent by the client should have this flag set.
    pub const ACK: u8 = 0b00010000;
    /// PSH – Push function. Asks to push the buffered data to the receiving application.
    pub const PSH: u8 = 0b00001000;
    /// RST – Reset the connection.
    pub const RST: u8 = 0b00000100;
    /// SYN – Synchronize sequence numbers. Only the first packet sent from each end
    /// should have this flag set.
    pub const SYN: u8 = 0b00000010;
    /// FIN – No more data from sender.
    pub const FIN: u8 = 0b00000001;

    pub const SYN_ACK: u8 = Self::SYN | Self::ACK;

    pub const FIN_ACK: u8 = Self::FIN | Self::ACK;
}

/// State of TCP connection.
// I decided that we are only managing the states of the connection that are relevant for our use case because
// we don't need to know every state of the TCP connection in a socket because we are not using sockets

pub enum HalfState {
    SynSeen,
    FinSeen,
    RstSeen,
    Established,
    Closed,
    Listen,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TcpState::Closed => "CLOSED",
                TcpState::Listen => "LISTEN",
                TcpState::SynSent => "SYN_SENT",
                TcpState::SynReceived => "SYN_RCVD",
                TcpState::Established => "ESTABLISHED",
                TcpState::FinWait1 => "FIN_WAIT_1",
                TcpState::FinWait2 => "FIN_WAIT_2",
                TcpState::CloseWait => "CLOSE_WAIT",
                TcpState::Closing => "CLOSING",
                TcpState::LastAck => "LAST_ACK",
                TcpState::TimeWait => "TIME_WAIT",
                TcpState::DeleteTcb => "DELETE_TCB",
            }
        )
    }
}
