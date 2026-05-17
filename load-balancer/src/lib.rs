use std::fmt;

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

/// State of TCP connection.
// I decided that we are only managing the states of the connection that are relevant for our use case because
// we don't need to know every state of the TCP connection in a socket because we are not using sockets

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum HalfState {
    SynSeen,
    FinSeen,
    RstSeen,
    Established,
    Closed,
    Closing,
    Listen,
}

impl fmt::Display for HalfState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                HalfState::SynSeen => "SYN_SEEN",
                HalfState::FinSeen => "FIN_SEEN",
                HalfState::RstSeen => "RST_SEEN",
                HalfState::Established => "ESTABLISHED",
                HalfState::Closed => "CLOSED",
                HalfState::Closing => "CLOSING",
                HalfState::Listen => "LISTEN",
            }
        )
    }
}
