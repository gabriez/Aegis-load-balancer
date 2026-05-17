use std::{collections::HashMap, sync::Arc};

use log::{error, info, warn};
use network_types::{ip::Ipv4Hdr, tcp};
use thiserror::Error;
use tokio::{sync, sync::RwLock, task::JoinSet, time};
use tokio_util::sync::CancellationToken;

use crate::{
    connections_balancer::BackendSelector,
    HalfState,
    TcpFlags::{ACK, FIN, RST, SYN},
};

const MIN_PORT: u16 = 32768;
const MAX_PORT: u16 = 60999;

/// PortsPool structure to manage the pool of available ports for NAT entries. It keeps track of the maximum number of ports and the number of ports currently available.
/// It provides methods to get a port from the pool and release a port back to the pool.
/// Ports are stored in big endian so we don't to transform them in the router
#[derive(Debug)]
pub struct PortsPool {
    max_ports: usize,
    ports_available: usize,
    ports: Vec<Option<u16>>,
}

impl PortsPool {
    pub fn new(min_port: u16, max_port: u16) -> Self {
        let capacity = (max_port - min_port + 1) as usize;
        let mut ports = Vec::with_capacity(capacity);

        for i in 0..capacity {
            ports.push(Some((min_port + i as u16).to_be() as u16));
        }
        Self {
            max_ports: capacity,
            ports_available: capacity,
            ports,
        }
    }

    pub fn get_port(&mut self) -> Option<u16> {
        if self.ports_available == 0 {
            return None;
        }
        self.ports_available -= 1;
        self.ports[self.ports_available].take()
    }

    pub fn release_port(&mut self, port: u16) {
        if self.ports_available < self.max_ports {
            self.ports[self.ports_available] = Some(port);
            self.ports_available += 1;
        }
    }

    pub fn get_max_ports(&self) -> usize {
        self.max_ports
    }
}

/// NatEntry structure to represent a NAT entry in the NAT table. It contains the client IP and port, the destination IP and port, the last seen timestamp, and the state of the TCP connection.
#[derive(Clone)]
pub struct NatEntry {
    // These addresses are the origin addresses from which the connection starts
    client_port: u16,
    client_ip: [u8; 4],

    // This port refers to the dst port of the TCP packet received from the client.
    client_dst_port: u16,

    // This addresses are the destination addresses to which the proxy port maps
    destination_port: u16,
    destination_ip: [u8; 4],

    tx_flag: sync::watch::Sender<TcpUpdateState>,
}

/// ClientKey structure to represent a key for the client map in the NAT table. It contains the client IP and port. This structure is used to quickly look up the NAT entry for a given client.
#[derive(Hash, Eq, PartialEq)]
pub struct ClientKey {
    client_ip: [u8; 4],
    client_port: u16,
}

impl ClientKey {
    pub fn new(client_ip: [u8; 4], client_port: u16) -> Self {
        Self {
            client_ip,
            client_port,
        }
    }
}

/// NAT Table structure to hold active NAT entries and mappings
pub struct NatTable {
    /// Maps the proxy port to the corresponding NAT entry. This allows for quick lookups of NAT entries based on the proxy port used in the TCP connection.
    nat_map: HashMap<u16, NatEntry>,

    /// Used to quickly look up the NAT entry for a given client IP and port. It maps the client key (IP and port) to the proxy port used in the NAT entry.
    client_map: HashMap<ClientKey, u16>,

    /// Manages the pool of available ports for NAT entries. It keeps track of the maximum number of ports and the number of ports currently available, and provides methods to get a port from the pool and release a port back to the pool.
    ports_pool: PortsPool,
}

impl NatTable {
    pub fn new(ports_pool: PortsPool) -> Self {
        Self {
            nat_map: HashMap::new(),
            client_map: HashMap::new(),
            ports_pool,
        }
    }

    pub fn new_conn(
        &mut self,
        client_port: u16,
        client_ip: [u8; 4],
        client_dst_port: u16,
        destination_port: u16,
        destination_ip: [u8; 4],
    ) -> Result<(u16, NatEntry), NatTableError> {
        let proxy_port = match self.ports_pool.get_port() {
            Some(port) => port,
            None => {
                // No available ports in the pool, handle this case as needed (e.g., return an error)
                return Err(NatTableError::NoAvailablePorts);
            }
        };

        let nat_entry = NatEntry {
            client_port,
            client_ip,
            client_dst_port,
            destination_port,
            destination_ip,
            tx_flag: sync::watch::channel(TcpUpdateState {
                flags: SYN,
                origin: PacketOrigin::Client,
            })
            .0,
        };

        let client_key = ClientKey::new(client_ip, client_port);

        if self.client_map.contains_key(&client_key) {
            return Err(NatTableError::NatEntryAlreadyExists);
        }

        if self.nat_map.contains_key(&proxy_port) {
            return Err(NatTableError::NatEntryAlreadyExists);
        }

        self.nat_map.insert(proxy_port, nat_entry.clone());
        self.client_map.insert(client_key, proxy_port);

        Ok((proxy_port, nat_entry))
    }

    pub fn get_nat_entry(&self, port: u16) -> Option<&NatEntry> {
        self.nat_map.get(&port)
    }

    pub fn client_key_exists(&self, key: &ClientKey) -> bool {
        self.client_map.contains_key(key)
    }

    pub fn nat_entry_exists(&self, port: u16) -> bool {
        self.nat_map.contains_key(&port)
    }

    pub fn get_active_connections(&self) -> usize {
        self.nat_map.len()
    }

    pub fn get_connection_port(&self, key: &ClientKey) -> Option<u16> {
        self.client_map.get(key).cloned()
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new(PortsPool::new(MIN_PORT, MAX_PORT))
    }
}

pub trait NatTableManager {
    /// Takes a proxy port as a parameter, checks if a NAT entry exists for the given port, and if it does,
    /// it removes the NAT entry from the nat_map, removes the client mapping from the client_map, releases the proxy port back to the ports pool, and returns the removed NAT entry. If no NAT entry exists for the given port, it returns an error indicating that the connection was not found.
    fn close_connection(&mut self, port: u16) -> Result<NatEntry, NatTableError>;

    /// Creates a new NAT entry for a given client IP and port, destination IP and port, and returns
    /// the assigned proxy port along with the created NAT entry. It first checks if there are available ports
    /// in the ports pool, and if there are, it assigns a proxy port from the pool. It then creates a new NAT entry with the provided client and destination information, and updates the nat_map and client_map accordingly. If no ports are available in the pool, or if a NAT entry already exists for the given client or proxy port, it returns an error indicating the issue.
    fn new_conn(
        &mut self,
        client_port: u16,
        client_ip: [u8; 4],
        client_dst_port: u16,
        destination_port: u16,
        destination_ip: [u8; 4],
    ) -> Result<(u16, NatEntry), NatTableError>;

    /// Takes a proxy port as a parameter and returns the corresponding NAT entry if it exists, or None if no NAT entry exists for the given port. This method allows for quick lookups of NAT entries based on the proxy port used in the TCP connection.
    fn get_nat_entry(&self, port: u16) -> Option<&NatEntry>;

    /// Checks if a client key (combination of client IP and port) exists in the client_map. It takes a ClientKey as a parameter and returns true if the client key exists in the client_map, or false if it does not. This method is useful for quickly determining if a NAT entry exists for a given client without needing to look up the proxy port first.
    fn client_key_exists(&self, key: &ClientKey) -> bool;

    /// Checks if a NAT entry exists for a given proxy port. It takes a proxy port as a parameter and returns true if a NAT entry exists for the given port in the nat_map, or false if it does not. This method allows for quick checks of the existence of NAT entries based on the proxy port used in the TCP connection.
    fn nat_entry_exists(&self, port: u16) -> bool;

    /// Returns the number of active connections currently managed by the NAT table. This method can be used to monitor the load on the NAT table and make decisions about resource management or scaling based on the number of active connections.
    fn get_active_connections(&self) -> usize;

    /// Takes a ClientKey as a parameter and returns the corresponding proxy port if a NAT entry exists for the given client key, or None if no NAT entry exists. This method allows for quick lookups of the proxy port associated with a given client IP and port, which can be useful for managing TCP connections and routing packets back to the client.
    fn get_connection_port(&self, key: &ClientKey) -> Option<u16>;
}

impl NatTableManager for NatTable {
    fn close_connection(&mut self, port: u16) -> Result<NatEntry, NatTableError> {
        if let Some(nat_entry) = self.nat_map.remove(&port) {
            self.client_map
                .remove(&ClientKey::new(nat_entry.client_ip, nat_entry.client_port));
            self.ports_pool.release_port(port);
            Ok(nat_entry)
        } else {
            Err(NatTableError::ConnectionNotFound)
        }
    }

    fn new_conn(
        &mut self,
        client_port: u16,
        client_ip: [u8; 4],
        client_dst_port: u16,
        destination_port: u16,
        destination_ip: [u8; 4],
    ) -> Result<(u16, NatEntry), NatTableError> {
        self.new_conn(
            client_port,
            client_ip,
            client_dst_port,
            destination_port,
            destination_ip,
        )
    }

    fn get_nat_entry(&self, port: u16) -> Option<&NatEntry> {
        self.get_nat_entry(port)
    }

    fn client_key_exists(&self, key: &ClientKey) -> bool {
        self.client_key_exists(key)
    }

    fn nat_entry_exists(&self, port: u16) -> bool {
        self.nat_entry_exists(port)
    }

    fn get_active_connections(&self) -> usize {
        self.get_active_connections()
    }

    fn get_connection_port(&self, key: &ClientKey) -> Option<u16> {
        self.get_connection_port(key)
    }
}

#[derive(Error, Debug)]
pub enum NatTableError {
    #[error("No available ports in the pool")]
    NoAvailablePorts,
    #[error("NAT entry not found for the given port")]
    NatEntryNotFound,
    #[error("NAT entry already exists for the given client")]
    NatEntryAlreadyExists,
    #[error("Connection does not exists")]
    ConnectionNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct TcpUpdateState {
    flags: u8, // The current state of the TCP connection, used to manage the connection lifecycle
    origin: PacketOrigin,
}

#[derive(Debug, Clone)]
pub struct TcpNewConn {
    proxy_port: u16,
    flags: u8, // The current state of the TCP connection, used to manage the connection lifecycle. Flags are stored in bytes, so we must use bitwise operations to check which flags are set.
    rx_flag: sync::watch::Receiver<TcpUpdateState>,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash)]
pub enum PacketOrigin {
    Client,
    Server,
}

async fn connections_manager(
    mut rx_new_conn: tokio::sync::mpsc::Receiver<TcpNewConn>,
    cancel_token: CancellationToken,
    nat_table: Arc<RwLock<dyn NatTableManager + 'static + Send + Sync>>,
) {
    let mut active_conn = JoinSet::new();
    loop {
        tokio::select! {
            conn_try = rx_new_conn.recv()  => {
                match conn_try {
                    Some(new_conn) => {
                        active_conn.spawn(tcp_state_manager(
                            cancel_token.clone(),
                            new_conn,
                        ));
                    },
                    None => {
                        warn!("Channel is closed for connections state manager. Finishing task");
                        break;
                    }
                }
            }
            _ = cancel_token.cancelled() => {
                    info!("Connections state manager received cancellation signal, shutting down.");
                    break;
                }
                Some(join_result) = active_conn.join_next() => {
                    match join_result {
                        Ok(proxy_port) => {
                            println!("TCP state manager task completed successfully.");
                            let mut lock_nat_table = nat_table.write().await;
                            if let Err(e) =  lock_nat_table.close_connection(proxy_port) {
                                eprintln!("Error closing connection for proxy port {}: {}", proxy_port, e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error in TCP state manager task: {}", e);
                        }
                    }
                }
        }
    }

    active_conn.shutdown().await;
}

// TODO: I need to study how to manage connections and the best patterns to follow in this case.
// I can use this guide: https://datatracker.ietf.org/doc/html/rfc9293#name-header-format and this one too https://medium.com/@itherohit/tcp-connection-establishment-an-in-depth-exploration-46031ef69908
// Also, I could check how other load balancers do it, like HAProxy and NGINX.
// Diagram stolen from
//                             +---------+ ---------\      active OPEN
//                             |  CLOSED |            \    -----------
//                             +---------+<---------\   \   create TCB
//                               |     ^              \   \  snd SYN
//                  passive OPEN |     |   CLOSE        \   \
//                  ------------ |     | ----------       \   \
//                   create TCB  |     | delete TCB         \   \
//                               V     |                      \   \
//           rcv RST (note 1)  +---------+            CLOSE    |    \
//        -------------------->|  LISTEN |          ---------- |     |
//       /                     +---------+          delete TCB |     |
//      /           rcv SYN      |     |     SEND              |     |
//     /           -----------   |     |    -------            |     V
// +--------+      snd SYN,ACK  /       \   snd SYN          +--------+
// |        |<-----------------           ------------------>|        |
// |  SYN   |                    rcv SYN                     |  SYN   |
// |  RCVD  |<-----------------------------------------------|  SENT  |
// |        |                  snd SYN,ACK                   |        |
// |        |------------------           -------------------|        |
// +--------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +--------+
//    |         --------------   |     |   -----------
//    |                x         |     |     snd ACK
//    |                          V     V
//    |  CLOSE                 +---------+
//    | -------                |  ESTAB  |
//    | snd FIN                +---------+
//    |                 CLOSE    |     |    rcv FIN
//    V                -------   |     |    -------
// +---------+         snd FIN  /       \   snd ACK         +---------+
// |  FIN    |<----------------          ------------------>|  CLOSE  |
// | WAIT-1  |------------------                            |   WAIT  |
// +---------+          rcv FIN  \                          +---------+
//   | rcv ACK of FIN   -------   |                          CLOSE  |
//   | --------------   snd ACK   |                         ------- |
//   V        x                   V                         snd FIN V
// +---------+               +---------+                    +---------+
// |FINWAIT-2|               | CLOSING |                    | LAST-ACK|
// +---------+               +---------+                    +---------+
//   |              rcv ACK of FIN |                 rcv ACK of FIN |
//   |  rcv FIN     -------------- |    Timeout=2MSL -------------- |
//   |  -------            x       V    ------------        x       V
//    \ snd ACK              +---------+delete TCB          +---------+
//      -------------------->|TIME-WAIT|------------------->| CLOSED  |
//                           +---------+                    +---------+

/// Helper function to manage TCP flags and update the connection state accordingly.
/// It takes the TCP flags, the origin of the packet (client or server), and mutable references to the
/// server and client connection states. Based on the flags received, it updates the connection states for both the
/// client and server, transitioning through states such as SYN seen, FIN seen, RST seen, established, and closed.
/// This function is crucial for managing the lifecycle of TCP connections in the connections manager.
pub fn set_conn_state(
    flags: u8,
    origin: PacketOrigin,
    server_state: &mut ConnState,
    client_state: &mut ConnState,
) {
    match flags {
        f if f & RST != 0 => {
            client_state.state = HalfState::RstSeen;
            server_state.state = HalfState::RstSeen;
        }

        f if f & SYN != 0 && f & ACK != 0 && origin == PacketOrigin::Server => {
            server_state.state = HalfState::SynSeen;
        }

        f if f & SYN != 0 && origin == PacketOrigin::Client => {
            client_state.state = HalfState::SynSeen;
        }
        f if f & FIN != 0 => {
            if origin == PacketOrigin::Client {
                client_state.state = HalfState::FinSeen;
            } else {
                server_state.state = HalfState::FinSeen;
            }
        }
        f if f & ACK != 0 => {
            if origin == PacketOrigin::Client
                && client_state.state == HalfState::SynSeen
                && server_state.state == HalfState::SynSeen
            {
                client_state.state = HalfState::Established;
                server_state.state = HalfState::Established;
            }

            if origin == PacketOrigin::Server && client_state.state == HalfState::FinSeen {
                client_state.state = HalfState::Closing;
            }

            if origin == PacketOrigin::Client && server_state.state == HalfState::FinSeen {
                server_state.state = HalfState::Closing;
            }
        }
        _ => {}
    }
}

/// Struct to represent state of TCP connections individually. It holds the origin of the last TCP packet received (client or server), the last TCP flags received, the current state of the TCP connection, and the timestamp of the last packet seen for this connection.
///  This struct is used to manage the state of each TCP connection in the connections manager.
#[derive(Debug)]
pub struct ConnState {
    last_tcp_flags: u8,
    state: HalfState,
    last_seen: time::Instant,
}

async fn tcp_state_manager(cancel_token: CancellationToken, tcp_new_conn: TcpNewConn) -> u16 {
    let timeout = time::sleep(time::Duration::from_secs(60));
    let TcpNewConn {
        proxy_port,
        flags,
        rx_flag,
    } = tcp_new_conn;

    tokio::pin!(timeout);

    let mut server_state = ConnState {
        last_tcp_flags: 0,
        state: HalfState::Listen,
        last_seen: time::Instant::now(),
    };

    let mut client_state = ConnState {
        last_tcp_flags: flags,
        state: HalfState::SynSeen,
        last_seen: time::Instant::now(),
    };

    let mut rx_flag_notified = rx_flag.clone();

    loop {
        tokio::select! {
            _ = &mut timeout => {
                // Handle connection timeout, e.g., remove the connection from the manager
                println!("Connection timed out: \n Server: {:?}\n Client: {:?}", server_state, client_state);
                return proxy_port;
            }
            _ = rx_flag_notified.changed() => {
                    let TcpUpdateState { flags, origin } = *rx_flag.borrow();

                    match origin {
                        PacketOrigin::Client => {
                            println!("TCP flag changed for client connection {:?}: {:?}", client_state, flags);
                            client_state.last_tcp_flags = flags;
                            client_state.last_seen = time::Instant::now();
                        }
                        PacketOrigin::Server => {
                            println!("TCP flag changed for server connection {:?}: {:?}", server_state, flags);
                            server_state.last_tcp_flags = flags;
                            server_state.last_seen = time::Instant::now();
                        }
                    }

                    if server_state.state == HalfState::Closing {
                        continue;
                    }

                    set_conn_state(flags, origin, &mut server_state, &mut client_state);

                    if server_state.state == HalfState::RstSeen || client_state.state == HalfState::RstSeen {
                        return proxy_port;
                    }

                    timeout.as_mut().reset(time::Instant::now() + time::Duration::from_secs(60));
            }
            _ = cancel_token.cancelled() => {
               return proxy_port ;
            }
        }
    }
}

#[derive(Debug)]
pub struct RedirectionAddress {
    pub origin_port: u16,
    pub dest_ip: [u8; 4],
    pub dest_port: u16,
}

/// AddressProvider structure provides an API to interact with the NatTable and control TCP connections state.
/// It holds a reference to the shared NAT table and a channel sender to send new connection events to the connections state manager.
#[derive(Clone)]
pub struct AddressProvider {
    nat_table: Arc<RwLock<dyn NatTableManager + 'static + Send + Sync>>,
    tx_new_conn: sync::mpsc::Sender<TcpNewConn>,
    backends: Arc<RwLock<dyn BackendSelector + 'static + Send + Sync>>,
}

impl AddressProvider {
    pub fn new(
        nat_table: Arc<RwLock<dyn NatTableManager + 'static + Send + Sync>>,
        tx_new_conn: tokio::sync::mpsc::Sender<TcpNewConn>,
        backends: Arc<RwLock<dyn BackendSelector + 'static + Send + Sync>>,
    ) -> Self {
        Self {
            nat_table,
            tx_new_conn,
            backends,
        }
    }

    pub fn check_origin(&self, ip: [u8; 4], port: u16) -> PacketOrigin {
        let backends = self.backends.blocking_read();
        if backends.backend_exist(ip, port) {
            PacketOrigin::Server
        } else {
            PacketOrigin::Client
        }
    }

    pub fn get_redirection_addr(
        &self,
        ipv4_hdr: &Ipv4Hdr,
        tcp_hdr: &tcp::TcpHdr,
    ) -> Option<RedirectionAddress> {
        let origin = self.check_origin(ipv4_hdr.src_addr, tcp_hdr.source);

        let flags = unsafe { ::core::mem::transmute(tcp_hdr._bitfield_1.get(8usize, 8u8) as u8) };

        match origin {
            PacketOrigin::Client => {
                if let Some((addr, tx)) =
                    self.get_backend_address(ipv4_hdr.src_addr, tcp_hdr.source)
                {
                    let _ = tx.send(TcpUpdateState { flags, origin });
                    return Some(addr);
                }

                self.new_connection(ipv4_hdr.src_addr, tcp_hdr.source, tcp_hdr.dest, flags)
            }
            PacketOrigin::Server => {
                if let Some((addr, tx)) = self.get_client_address(tcp_hdr.dest) {
                    let _ = tx.send(TcpUpdateState { flags, origin });
                    return Some(addr);
                }
                None
            }
        }
    }

    fn new_connection(
        &self,
        client_ip: [u8; 4],
        client_port: u16,
        client_dst_port: u16,
        flags: u8,
    ) -> Option<RedirectionAddress> {
        let destination = {
            let mut backends = self.backends.blocking_write();
            backends.select_backend()
        };

        if flags & SYN == 0 {
            return None;
        }

        if let Some((destination_ip, destination_port)) = destination {
            let mut lock_nat_table = self.nat_table.blocking_write();
            match lock_nat_table.new_conn(
                client_port,
                client_ip,
                client_dst_port,
                destination_port,
                destination_ip,
            ) {
                Ok((proxy_port, nat_entry)) => {
                    let tcp_new_conn = TcpNewConn {
                        proxy_port,
                        flags,
                        rx_flag: nat_entry.tx_flag.subscribe(),
                    };
                    if let Err(e) = self.tx_new_conn.blocking_send(tcp_new_conn) {
                        error!(
                            "Failed to send new connection event to state manager: {}",
                            e
                        );
                    }
                    let mut backends = self.backends.blocking_write();
                    backends.increase_conn(destination_ip, destination_port);
                    Some(RedirectionAddress {
                        origin_port: proxy_port,
                        dest_ip: destination_ip,
                        dest_port: destination_port,
                    })
                }
                Err(e) => {
                    error!(
                        "Failed to create new NAT entry for client {}:{} -> {}:{} : {}",
                        client_ip
                            .iter()
                            .map(|b| b.to_string())
                            .collect::<Vec<String>>()
                            .join("."),
                        client_port,
                        destination_ip
                            .iter()
                            .map(|b| b.to_string())
                            .collect::<Vec<String>>()
                            .join("."),
                        destination_port,
                        e
                    );
                    None
                }
            }
        } else {
            warn!(
                "No backend available for new connection from client {}:{} -> {}:{}",
                client_ip
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<String>>()
                    .join("."),
                client_port,
                "N/A",
                "N/A"
            );
            None
        }
    }

    pub fn get_backend_address(
        &self,
        ip: [u8; 4],
        port: u16,
    ) -> Option<(RedirectionAddress, sync::watch::Sender<TcpUpdateState>)> {
        let client_key = ClientKey::new(ip, port);
        let lock_nat_table = self.nat_table.blocking_read();

        if lock_nat_table.client_key_exists(&client_key) {
            if let Some(proxy_port) = lock_nat_table.get_connection_port(&client_key) {
                if let Some(nat_entry) = lock_nat_table.get_nat_entry(proxy_port) {
                    return Some((
                        RedirectionAddress {
                            origin_port: proxy_port,
                            dest_ip: nat_entry.destination_ip,
                            dest_port: nat_entry.destination_port,
                        },
                        nat_entry.tx_flag.clone(),
                    ));
                }
            }
        }

        None
    }

    pub fn get_client_address(
        &self,
        proxy_port: u16,
    ) -> Option<(RedirectionAddress, sync::watch::Sender<TcpUpdateState>)> {
        let lock_nat_table = self.nat_table.blocking_read();

        if let Some(nat_entry) = lock_nat_table.get_nat_entry(proxy_port) {
            return Some((
                RedirectionAddress {
                    origin_port: nat_entry.client_dst_port,
                    dest_ip: nat_entry.client_ip,
                    dest_port: nat_entry.client_port,
                },
                nat_entry.tx_flag.clone(),
            ));
        }

        None
    }
}

pub trait RouteAddress {
    /// Get redirection address is the function that will be called by the XDP program to get the backend address to which the packet should be redirected. It takes the ipv4_header and tpc_header as parameters
    /// and returns the backend IP and port if a NAT entry exists for the given client, or None if no NAT entry exists. This function is responsible for determining the appropriate redirection address based on the incoming packet's headers and the current state of the NAT table.
    fn get_redirection_addr(
        &self,
        ipv4_hdr: &Ipv4Hdr,
        tcp_hdr: &tcp::TcpHdr,
    ) -> Option<RedirectionAddress>;
}

impl RouteAddress for AddressProvider {
    fn get_redirection_addr(
        &self,
        ipv4_hdr: &Ipv4Hdr,
        tcp_hdr: &tcp::TcpHdr,
    ) -> Option<RedirectionAddress> {
        self.get_redirection_addr(ipv4_hdr, tcp_hdr)
    }
}

/// build_connections_manager is a function that initializes the connections manager and returns a tuple containing a function to start the connections manager task and an AddressProvider instance. The connections manager task is responsible for managing the state of active TCP connections,
/// including handling new connection events, updating connection states based on TCP flags, and cleaning up connections that have timed out.
/// The AddressProvider instance provides an API to interact with the NAT table and control TCP connection states, allowing for the retrieval of redirection addresses and the management of new connections.
/// The address provider can be used in multiple threads, but if every instance is dropped, then the connections manager will stop working, since it relies on the channel to receive new connection events.
/// This follows a frontend - backend pattern.
pub fn build_connections_manager(
    nat_table: Arc<RwLock<dyn NatTableManager + 'static + Send + Sync>>,
    backends: Arc<RwLock<dyn BackendSelector + 'static + Send + Sync>>,
) -> (
    impl FnOnce(CancellationToken) -> tokio::task::JoinHandle<()>,
    AddressProvider,
) {
    let (tx_new_conn, rx_new_conn) = tokio::sync::mpsc::channel(100);
    let address_provider =
        AddressProvider::new(Arc::clone(&nat_table), tx_new_conn.clone(), backends);

    let manager_handle = move |cancel_token: CancellationToken| {
        tokio::spawn(connections_manager(rx_new_conn, cancel_token, nat_table))
    };

    (manager_handle, address_provider)
}
