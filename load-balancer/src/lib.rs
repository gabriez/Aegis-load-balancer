use std::fmt;

use network_types::tcp::TcpHdr;
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
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum TcpFlagsEnum {
    CWR,
    ECE,
    URG,
    ACK,
    PSH,
    RST,
    SYN,
    FIN,
}

impl TcpFlagsEnum {
    pub fn from_u8(flag: u8) -> Result<Self, TcpFlagsError> {
        match flag {
            TcpFlags::CWR => Ok(TcpFlagsEnum::CWR),
            TcpFlags::ECE => Ok(TcpFlagsEnum::ECE),
            TcpFlags::URG => Ok(TcpFlagsEnum::URG),
            TcpFlags::ACK => Ok(TcpFlagsEnum::ACK),
            TcpFlags::PSH => Ok(TcpFlagsEnum::PSH),
            TcpFlags::RST => Ok(TcpFlagsEnum::RST),
            TcpFlags::SYN => Ok(TcpFlagsEnum::SYN),
            TcpFlags::FIN => Ok(TcpFlagsEnum::FIN),
            _ => Err(TcpFlagsError::InvalidFlagValue(flag)),
        }
    }

    pub fn from_tcp_hdr(tcp_hdr: &TcpHdr) -> Self {
        let flags_byte = tcp_hdr._bitfield_1.get(0usize, 4u8) as u8;
        TcpFlagsEnum::from_u8(flags_byte).unwrap_or(TcpFlagsEnum::ACK)
    }
}

#[derive(Error, Debug)]
pub enum TcpFlagsError {
    #[error("Invalid TCP flag value: {0}")]
    InvalidFlagValue(u8),
}

/// State of TCP connection.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
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
