// xdp-proto-counter-ebpf — Capítulo 11: Lado kernel en Aya (Rust)
//
// Este es el equivalente de xdp_proto_counter.bpf.c pero escrito en Rust.
// Compila directamente a BPF bytecode con el target bpfeb-unknown-none.
//
// Nota: #![no_std] y #![no_main] son obligatorios — estamos en el kernel,
// no hay runtime de Rust disponible.

#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
use core::mem;

// Índices del array para cada protocolo
const PROTO_TCP: u32 = 0;
const PROTO_UDP: u32 = 1;
const PROTO_ICMP: u32 = 2;
const PROTO_OTHER: u32 = 3;

// Array map: contadores por protocolo (4 entries)
#[map]
static PROTO_STATS: Array<u64> = Array::with_max_entries(4, 0);

// Constantes de protocolo de red
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

// Headers de red (definidos manualmente en no_std)
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16, // big-endian
}

#[repr(C)]
struct IpHdr {
    _version_ihl: u8,
    _tos: u8,
    _tot_len: u16,
    _id: u16,
    _frag_off: u16,
    _ttl: u8,
    protocol: u8,
    _check: u16,
    _saddr: u32,
    _daddr: u32,
}

#[xdp]
pub fn xdp_proto_counter(ctx: XdpContext) -> u32 {
    match try_xdp_proto_counter(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_proto_counter(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Parsear Ethernet header — bounds check
    let eth_hdr_size = mem::size_of::<EthHdr>();
    if data + eth_hdr_size > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let eth = unsafe { &*(data as *const EthHdr) };

    // Solo procesar IPv4 (h_proto está en big-endian)
    if u16::from_be(eth.h_proto) != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parsear IP header — bounds check
    let ip_offset = data + eth_hdr_size;
    let ip_hdr_size = mem::size_of::<IpHdr>();
    if ip_offset + ip_hdr_size > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = unsafe { &*(ip_offset as *const IpHdr) };

    // Clasificar protocolo
    let proto_idx = match ip.protocol {
        IPPROTO_TCP => PROTO_TCP,
        IPPROTO_UDP => PROTO_UDP,
        IPPROTO_ICMP => PROTO_ICMP,
        _ => PROTO_OTHER,
    };

    // Incrementar contador
    if let Some(count) = unsafe { PROTO_STATS.get_ptr_mut(proto_idx) } {
        unsafe { *count += 1 };
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
