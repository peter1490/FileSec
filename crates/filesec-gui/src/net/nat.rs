//! Automatic router port-mapping via **NAT-PMP** (RFC 6886) — a tiny, vendored,
//! dependency-free UDP exchange with the local gateway. No UPnP, no third-party
//! "what is my IP" server: the public address is reported by the gateway itself,
//! preserving FileSec's no-server stance.
//!
//! Internet mode asks the router to forward an external TCP port to this machine
//! and learns the public IP. If the router does not speak NAT-PMP (some only do
//! UPnP-IGD — a possible future addition) or SSDP/NAT-PMP is blocked, every call
//! here fails cleanly and the caller falls back to LAN-only operation with manual
//! port-forwarding guidance.
//!
//! Mappings are requested with a finite lease and refreshed while listening, so a
//! crash leaves at most a short-lived stale mapping; [`PortMapping`] also unmaps on
//! `Drop`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// The well-known NAT-PMP / PCP UDP port on the gateway.
const NATPMP_PORT: u16 = 5351;
/// Lease length requested for a mapping (seconds). Refreshed at roughly half this.
const LEASE_SECS: u32 = 3600;
/// NAT-PMP opcodes.
const OP_EXTERNAL: u8 = 0;
const OP_MAP_TCP: u8 = 2;
/// Successful responses set the high bit (0x80) on the opcode.
const RESP_FLAG: u8 = 0x80;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn be_u16(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(off)?, *buf.get(off + 1)?]))
}

fn be_u32(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *buf.get(off)?,
        *buf.get(off + 1)?,
        *buf.get(off + 2)?,
        *buf.get(off + 3)?,
    ]))
}

/// Send a NAT-PMP request to the gateway and read a validated response, retrying
/// with exponential backoff (per the RFC's recommended schedule).
fn transact(
    gateway: Ipv4Addr,
    request: &[u8],
    expected_op: u8,
    min_len: usize,
) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((gateway, NATPMP_PORT))?;
    let mut timeout = Duration::from_millis(250);
    let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "no response from the gateway");
    for _ in 0..4 {
        socket.set_read_timeout(Some(timeout))?;
        socket.send(request)?;
        let mut buf = [0u8; 32];
        match socket.recv(&mut buf) {
            Ok(n) => {
                let resp = buf.get(..n).unwrap_or(&[]);
                if resp.len() < min_len {
                    last_err = invalid("short NAT-PMP response");
                } else if resp.first() != Some(&0) {
                    last_err = invalid("unexpected NAT-PMP version");
                } else if resp.get(1) != Some(&(RESP_FLAG | expected_op)) {
                    last_err = invalid("unexpected NAT-PMP opcode");
                } else if be_u16(resp, 2) != Some(0) {
                    last_err = invalid("the gateway refused the NAT-PMP request");
                } else {
                    return Ok(resp.to_vec());
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => last_err = e,
        }
        timeout = timeout.saturating_mul(2);
    }
    Err(last_err)
}

/// Ask the gateway for the network's public IPv4 address.
fn external_address(gateway: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let resp = transact(gateway, &[0, OP_EXTERNAL], OP_EXTERNAL, 12)?;
    let ip = be_u32(&resp, 8).ok_or_else(|| invalid("malformed external-address response"))?;
    Ok(Ipv4Addr::from(ip))
}

/// Request (or refresh, or with `lifetime = 0` remove) a TCP port mapping.
/// Returns the actually-assigned external port.
fn map_tcp(
    gateway: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> io::Result<u16> {
    let mut req = Vec::with_capacity(12);
    req.push(0); // version
    req.push(OP_MAP_TCP);
    req.extend_from_slice(&[0, 0]); // reserved
    req.extend_from_slice(&internal_port.to_be_bytes());
    req.extend_from_slice(&external_port.to_be_bytes());
    req.extend_from_slice(&lifetime.to_be_bytes());
    let resp = transact(gateway, &req, OP_MAP_TCP, 16)?;
    be_u16(&resp, 10).ok_or_else(|| invalid("malformed mapping response"))
}

/// A live router port mapping. Refreshes are driven by the caller; the mapping is
/// best-effort removed on drop (the finite lease backstops a crash).
pub struct PortMapping {
    gateway: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    public_ip: Ipv4Addr,
}

impl PortMapping {
    /// Discover the gateway, learn the public IP, and map an external TCP port to
    /// `internal_port` on this machine. Returns a clear error string on any failure
    /// so the caller can fall back to LAN-only.
    pub fn create(internal_port: u16) -> Result<Self, String> {
        let gateway = discover_gateway().ok_or_else(|| {
            "could not find the router's address (no default gateway)".to_string()
        })?;
        let public_ip = external_address(gateway)
            .map_err(|e| format!("the router did not report a public address: {e}"))?;
        let external_port = map_tcp(gateway, internal_port, internal_port, LEASE_SECS)
            .map_err(|e| format!("the router refused to open a port: {e}"))?;
        Ok(Self {
            gateway,
            internal_port,
            external_port,
            public_ip,
        })
    }

    /// The public `ip:port` peers should be given.
    pub fn public_addr(&self) -> SocketAddr {
        SocketAddr::from((self.public_ip, self.external_port))
    }

    /// Renew the lease (call at roughly half the lease interval while listening).
    pub fn refresh(&self) -> io::Result<()> {
        map_tcp(
            self.gateway,
            self.internal_port,
            self.external_port,
            LEASE_SECS,
        )
        .map(|_| ())
    }

    /// How often to refresh, in seconds.
    pub const fn refresh_interval_secs() -> u64 {
        (LEASE_SECS / 2) as u64
    }
}

impl Drop for PortMapping {
    fn drop(&mut self) {
        // Best-effort: a lifetime of 0 removes the mapping; ignore errors (the
        // finite lease cleans up regardless).
        let _ = map_tcp(self.gateway, self.internal_port, 0, 0);
    }
}

/// Best-effort discovery of the default gateway (the router), per OS. Returns
/// `None` if it cannot be determined, in which case internet mode is unavailable
/// and the caller stays LAN-only.
pub fn discover_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        linux_gateway()
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        bsd_gateway()
    }
    #[cfg(target_os = "windows")]
    {
        windows_gateway()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "windows"
    )))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_gateway() -> Option<Ipv4Addr> {
    // /proc/net/route: the default route has Destination 00000000; the Gateway
    // column is the 32-bit address in little-endian hex.
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in table.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _iface = cols.next()?;
        let dest = cols.next()?;
        let gw = cols.next()?;
        if dest == "00000000" {
            let raw = u32::from_str_radix(gw, 16).ok()?;
            if raw == 0 {
                continue;
            }
            return Some(Ipv4Addr::from(raw.to_le_bytes()));
        }
    }
    None
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
fn bsd_gateway() -> Option<Ipv4Addr> {
    // `route -n get default` prints a line like "    gateway: 192.168.1.1".
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("gateway:") {
            if let Ok(ip) = rest.trim().parse::<Ipv4Addr>() {
                return Some(ip);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_gateway() -> Option<Ipv4Addr> {
    use std::os::windows::process::CommandExt;
    // CREATE_NO_WINDOW: don't flash a console window for the helper query.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|line| line.trim().parse::<Ipv4Addr>().ok())
}
