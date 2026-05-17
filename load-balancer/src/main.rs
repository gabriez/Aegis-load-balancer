use std::{
    os::fd::AsFd,
    sync::{Arc, RwLock},
    thread::spawn,
};

use agave_afxdp::{
    device::{NetworkDevice, QueueId, RingSizes},
    socket::Socket,
    umem::{PageAlignedMemory, SliceUmem},
};
use anyhow::Context as _;
use aya::{
    maps::{xdp::XskMap, HashMap, MapData, MapError},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use libc::{sysconf, _SC_PAGESIZE};
use load_balancer::{
    config::Config,
    connections_balancer::{BackendSelector, Backends},
    connections_manager::{build_connections_manager, AddressProvider, NatTable, NatTableManager},
    pipeline::{
        free_tx_frames, insert_frames_fill_ring, process_packets, receive_packets, recycle_frames,
        release_cq_frames, send_packets, FramesManager, PACKETS_BATCH,
    },
};
use load_balancer_common::MAX_BLOCKLIST_ENTRIES;
use log::{debug, warn};
use tokio::{signal, sync::RwLock as TkRwLock};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
struct Opt {
    /// Network interface to attach the XDP program to
    #[clap(short, long, default_value = "lo")]
    iface: String,

    /// Amount of queues to create sockets for
    #[clap(short, long, default_value_t = 1)]
    queues: u64,

    /// Path to the configuration file
    #[clap(short, long, default_value = "config.json")]
    config_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut fut_joinset: tokio::task::JoinSet<anyhow::Result<()>> = tokio::task::JoinSet::new();
    let cancellation_token = CancellationToken::new();
    // TODO: implement configuration for PortsPool, meanwhile we are using NatTable default to avoid configuration
    // let ports_pool = PortsPool::new(min_port, max_port);
    let nat_table = NatTable::default();
    let shared_nat_table = Arc::new(TkRwLock::new(nat_table))
        as Arc<TkRwLock<dyn NatTableManager + 'static + Send + Sync>>;

    let backends_manager = Backends::default();
    let shared_backends = Arc::new(TkRwLock::new(backends_manager));

    let (nat_table_manager, address_provider) = build_connections_manager(
        shared_nat_table,
        Arc::clone(&shared_backends) as Arc<TkRwLock<dyn BackendSelector + 'static + Send + Sync>>,
    );

    let cloned_cancel_token = cancellation_token.clone();
    fut_joinset.spawn(async move {
        nat_table_manager(cloned_cancel_token).await?;
        Ok(())
    });

    let cloned_cancel_token = cancellation_token.clone();
    fut_joinset.spawn(async move {
        let ctrl_c = signal::ctrl_c();
        ctrl_c.await?;

        cloned_cancel_token.cancel();
        Ok(())
    });

    fut_joinset.spawn(async { run_af_xdp_socket(cancellation_token, address_provider).await });

    println!("Waiting for Ctrl-C...");
    while let Some(fut) = fut_joinset.join_next().await {
        fut??;
    }
    println!("Exiting...");

    Ok(())
}

async fn run_af_xdp_socket(
    cancellation_token: CancellationToken,
    address_provider: AddressProvider,
) -> anyhow::Result<()> {
    let opt: Opt = Opt::parse();
    let Opt {
        iface,
        queues,
        config_path,
    } = opt;

    let config = Config::from_file(&config_path).await?;
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/load-balancer"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = ebpf.program_mut("load_balancer").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    log::info!("XDP program attached to interface {}", iface);
    let xsk_map: Arc<RwLock<XskMap<MapData>>> = if let Some(map) = ebpf.take_map("XSK_SOCKS") {
        Arc::new(RwLock::new(map.try_into()?))
    } else {
        anyhow::bail!("failed to find XSK map");
    };

    // Only accept 1024 entries in the blocklist, which should be enough for this PoC
    let mut blocklist_map: HashMap<_, [u8; 4], u64> = if let Some(map) = ebpf.take_map("BLOCKLIST")
    {
        map.try_into()?
    } else {
        anyhow::bail!("failed to find blocklist map");
    };

    for (i, ip) in config.blocklist.iter().enumerate() {
        if i >= MAX_BLOCKLIST_ENTRIES as usize {
            break;
        }
        match blocklist_map.insert(ip, 0, 0) {
            Err(MapError::OutOfBounds {
                index: _,
                max_entries,
            }) => {
                log::warn!("Blocklist too big for actual capacity. Max capacity {}. \n IP addresses took until IP: {:?}", max_entries, ip );
            }
            Err(err) => {
                anyhow::bail!("Blocklist map err: {:?}", err);
            }
            Ok(_) => {}
        }
    }

    let mut joinset = Vec::new();

    for queue in 0..queues {
        joinset.push(build_thread_tx_loop(
            queue,
            &iface,
            Arc::clone(&xsk_map),
            cancellation_token.clone(),
            address_provider.clone(),
        )?);
    }

    for handle in joinset {
        handle.join().expect("Thread panicked")?;
    }

    Ok(())
}

fn build_thread_tx_loop(
    queue: u64,
    iface: impl AsRef<str>,
    xsk_map: Arc<RwLock<XskMap<MapData>>>,
    cancellation_token: CancellationToken,
    address_provider: AddressProvider,
) -> anyhow::Result<std::thread::JoinHandle<anyhow::Result<()>>> {
    let iface = iface.as_ref().to_string();

    let task = move || {
        // TODO: move network_device creation outside of the loop and clone it for each thread.
        let network_device = NetworkDevice::new(&iface).expect("failed to find the network device");
        let queue_id = QueueId(queue);

        let device_queue = network_device
            .open_queue(queue_id)
            .expect("failed to open queue for AF_XDP socket");

        let RingSizes {
            rx: rx_size,
            tx: tx_size,
        } = device_queue.ring_sizes().unwrap_or_else(|| {
            log::info!(
                "using default ring sizes for {} queue {queue_id:?}",
                network_device.name()
            );
            RingSizes::default()
        });

        let frame_count = (rx_size + tx_size) * 2;
        let frame_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

        // try to allocate huge pages first, then fall back to regular pages
        const HUGE_2MB: usize = 2 * 1024 * 1024;
        let mut aligned_memory =
            PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
                .or_else(|_| {
                    log::warn!("huge page alloc failed, falling back to regular page size");
                    PageAlignedMemory::alloc(frame_size, frame_count)
                })
                .unwrap();

        let umem = SliceUmem::new(&mut aligned_memory, frame_size as u32)?;

        let (mut socket, rx, tx) = Socket::new(
            device_queue,
            umem,
            false,
            rx_size * 2,
            rx_size,
            tx_size * 2,
            tx_size,
        )?;

        {
            let mut xsk_map = xsk_map
                .write()
                .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
            xsk_map.set(queue as u32, socket.as_fd(), 0)?;
        }

        let mut frames_manager = FramesManager::build_with_capacity(frame_count);

        let umem = socket.umem();
        frames_manager
            .insert_frames_from_umem(umem)
            .expect("failed to insert frames from umem. Space is full");

        let mut fill_ring = rx.fill;
        let mut completion_ring = tx.completion;

        insert_frames_fill_ring(&mut fill_ring, &mut frames_manager);
        fill_ring.sync(false);

        let mut rx_ring = rx
            .ring
            .expect(&format!("RX ring is not available in queue: {}", queue));
        let mut tx_ring = tx
            .ring
            .expect(&format!("TX ring is not available in queue: {}", queue));
        rx_ring.sync(false);

        while !cancellation_token.is_cancelled() {
            rx_ring.sync(false);
            tx_ring.sync(false);

            let available_packets = rx_ring.available();

            if available_packets == 0 {
                // Maybe RX is not receiving packets, so we can release completion ring frames and recycle fill ring frames in case there are any
                release_cq_frames(umem, &mut completion_ring);
                recycle_frames(umem, &mut fill_ring, &mut frames_manager)?;

                // Wake up if needed
                if fill_ring.needs_wakeup() {
                    fill_ring.wake()?;
                }
                continue;
            }

            let mut batch_size = PACKETS_BATCH.min(available_packets);

            batch_size = free_tx_frames(batch_size, &mut tx_ring);

            let received_pkts = receive_packets(batch_size, &mut rx_ring);

            rx_ring.commit();

            let processed_pkts = process_packets(received_pkts, umem, &address_provider);

            send_packets(&mut tx_ring, processed_pkts, umem);

            // Completion Ring
            release_cq_frames(umem, &mut completion_ring);

            // Frame recycling
            recycle_frames(umem, &mut fill_ring, &mut frames_manager)?;
        }
        Ok(())
    };
    let thread_handle = spawn(task);
    // });
    Ok(thread_handle)
}
