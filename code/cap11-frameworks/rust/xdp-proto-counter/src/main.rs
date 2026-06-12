// xdp-proto-counter — Capítulo 11: User space en Aya (Rust)
//
// Equivalente del main.go pero en Rust. Demuestra:
// - Cargar programa BPF compilado desde Aya
// - Adjuntar XDP a una interfaz
// - Leer stats del array map periódicamente
//
// Uso:
//   cargo build --release
//   sudo ./target/release/xdp-proto-counter --iface lo

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::Array,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use clap::Parser;
use log::info;
use std::time::Duration;
use tokio::{signal, time};

#[derive(Parser)]
#[command(name = "xdp-proto-counter")]
#[command(about = "Contador XDP de paquetes por protocolo (Aya/Rust)")]
struct Args {
    /// Interfaz de red donde adjuntar XDP
    #[arg(short, long, default_value = "lo")]
    iface: String,
}

// Nombres legibles de los protocolos
const PROTO_NAMES: [&str; 4] = ["TCP", "UDP", "ICMP", "Otro"];

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    println!("═══════════════════════════════════════════════════════════════");
    println!("  Capítulo 11 — Contador XDP por Protocolo (Aya/Rust)");
    println!("═══════════════════════════════════════════════════════════════");
    println!();

    // Cargar el programa BPF (compilado del crate xdp-proto-counter-ebpf)
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfeb-unknown-none/debug/xdp-proto-counter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfeb-unknown-none/release/xdp-proto-counter"
    ))?;

    // Adjuntar programa XDP
    let program: &mut Xdp = bpf
        .program_mut("xdp_proto_counter")
        .unwrap()
        .try_into()?;
    program.load()?;
    program
        .attach(&args.iface, XdpFlags::SKB_MODE)
        .context(format!("Error adjuntando XDP a '{}'", args.iface))?;

    info!("XDP adjuntado a '{}' exitosamente", args.iface);
    println!("  ✅ XDP adjuntado a '{}' (modo SKB)", args.iface);
    println!();
    println!("─────────────────────────────────────────────────────────────");
    println!("  📡 Contando paquetes por protocolo. Ctrl+C para salir.");
    println!("─────────────────────────────────────────────────────────────");
    println!();

    // Loop principal: mostrar stats cada 2 segundos
    let mut interval = time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n  👋 Programa XDP removido. Adiós.");
                break;
            }
            _ = interval.tick() => {
                print_stats(&bpf)?;
            }
        }
    }

    Ok(())
}

fn print_stats(bpf: &Ebpf) -> Result<()> {
    let proto_stats: Array<_, u64> = Array::try_from(
        bpf.map("PROTO_STATS").unwrap(),
    )?;

    print!("  📊 ");
    for i in 0u32..4 {
        let count = proto_stats.get(&i, 0).unwrap_or(0);
        print!("{}={}", PROTO_NAMES[i as usize], count);
        if i < 3 {
            print!(" | ");
        }
    }
    println!();

    Ok(())
}
