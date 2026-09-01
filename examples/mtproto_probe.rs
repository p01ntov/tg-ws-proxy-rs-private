//! End-to-end latency probe for an already running local MTProto proxy.
//!
//! Unlike a TCP-only health check, this sends an unencrypted `req_pq_multi`
//! through the proxy and accepts the sample only after Telegram returns a
//! matching `resPQ`. This exercises the inbound obfuscation handshake, route
//! selection, WebSocket or fallback transport, and the response path without
//! requiring a Telegram account or API credentials.

use std::env;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cipher::StreamCipher;
use rand::RngCore;
use tg_ws_proxy_rs::crypto::{ProtoTag, generate_client_handshake, secret_key};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;
const RES_PQ: u32 = 0x0516_2463;
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

fn mtproto_message(nonce: [u8; 16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(&REQ_PQ_MULTI.to_le_bytes());
    body.extend_from_slice(&nonce);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch");
    let fractional = (u64::from(now.subsec_nanos()) << 32) / 1_000_000_000;
    let message_id = ((now.as_secs() << 32) | fractional) & !3;

    let mut message = Vec::with_capacity(20 + body.len());
    message.extend_from_slice(&0_u64.to_le_bytes());
    message.extend_from_slice(&message_id.to_le_bytes());
    message.extend_from_slice(&(body.len() as u32).to_le_bytes());
    message.extend_from_slice(&body);
    message
}

async fn probe_once(addr: &str, secret: &[u8], dc: i16) -> Result<Duration, String> {
    let started = Instant::now();
    let stream = timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| "TCP connect timeout".to_string())?
        .map_err(|e| format!("TCP connect: {e}"))?;
    stream
        .set_nodelay(true)
        .map_err(|e| format!("TCP_NODELAY: {e}"))?;
    let (mut reader, mut writer) = stream.into_split();

    let (handshake, mut enc, mut dec) =
        generate_client_handshake(secret, dc, ProtoTag::PaddedIntermediate);
    timeout(PROBE_TIMEOUT, writer.write_all(&handshake))
        .await
        .map_err(|_| "handshake write timeout".to_string())?
        .map_err(|e| format!("handshake write: {e}"))?;

    let mut nonce = [0_u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    let message = mtproto_message(nonce);
    let mut packet = Vec::with_capacity(4 + message.len());
    packet.extend_from_slice(&(message.len() as u32).to_le_bytes());
    packet.extend_from_slice(&message);
    enc.apply_keystream(&mut packet);

    timeout(PROBE_TIMEOUT, writer.write_all(&packet))
        .await
        .map_err(|_| "request write timeout".to_string())?
        .map_err(|e| format!("request write: {e}"))?;

    let mut header = [0_u8; 4];
    timeout(PROBE_TIMEOUT, reader.read_exact(&mut header))
        .await
        .map_err(|_| "response timeout".to_string())?
        .map_err(|e| format!("response header: {e}"))?;
    dec.apply_keystream(&mut header);
    let payload_len = (u32::from_le_bytes(header) & 0x7fff_ffff) as usize;
    if !(40..=4096).contains(&payload_len) {
        return Err(format!("invalid transport length {payload_len}"));
    }

    let mut payload = vec![0_u8; payload_len];
    timeout(PROBE_TIMEOUT, reader.read_exact(&mut payload))
        .await
        .map_err(|_| "response body timeout".to_string())?
        .map_err(|e| format!("response body: {e}"))?;
    dec.apply_keystream(&mut payload);

    if payload.len() < 40 {
        return Err("short MTProto response".to_string());
    }
    if payload[..8] != [0_u8; 8] {
        return Err("encrypted response received before authorization".to_string());
    }
    let body_len = u32::from_le_bytes(payload[16..20].try_into().unwrap()) as usize;
    if body_len < 20 || 20 + body_len > payload.len() {
        return Err(format!("invalid MTProto body length {body_len}"));
    }
    let constructor = u32::from_le_bytes(payload[20..24].try_into().unwrap());
    if constructor != RES_PQ {
        return Err(format!("unexpected constructor 0x{constructor:08x}"));
    }
    if payload[24..40] != nonce {
        return Err("resPQ nonce mismatch".to_string());
    }

    Ok(started.elapsed())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        println!("Usage: TG_SECRET=<hex> mtproto_probe [HOST:PORT] [DC] [COUNT]");
        println!("Use a negative DC index to probe its media route, for example -2.");
        return;
    }
    if args.len() > 4 {
        eprintln!("Usage: TG_SECRET=<hex> mtproto_probe [HOST:PORT] [DC] [COUNT]");
        std::process::exit(2);
    }
    let addr = args.get(1).map(String::as_str).unwrap_or("127.0.0.1:1443");
    let dc = args.get(2).map_or(2, |value| {
        value.parse::<i16>().unwrap_or_else(|_| {
            eprintln!("DC must be an integer");
            std::process::exit(2);
        })
    });
    if !matches!(dc.unsigned_abs(), 1..=5 | 203) {
        eprintln!("DC must be 1..5 or 203; use a negative value for a media route");
        std::process::exit(2);
    }
    let count = args.get(3).map_or(12, |value| {
        value.parse::<usize>().unwrap_or_else(|_| {
            eprintln!("COUNT must be an integer");
            std::process::exit(2);
        })
    });
    if count == 0 {
        eprintln!("COUNT must be greater than zero");
        std::process::exit(2);
    }
    let secret_hex = env::var("TG_SECRET").unwrap_or_else(|_| {
        eprintln!("TG_SECRET is required and must contain one MTProto proxy secret");
        std::process::exit(2);
    });
    let secret_raw = hex::decode(secret_hex.trim()).unwrap_or_else(|_| {
        eprintln!("TG_SECRET must be hexadecimal");
        std::process::exit(2);
    });
    let secret = secret_key(&secret_raw);
    if secret.len() != 16 {
        eprintln!("TG_SECRET must contain a 16-byte key, optionally with a dd/ee prefix");
        std::process::exit(2);
    }

    let mut samples = Vec::with_capacity(count);
    let mut failures = Vec::new();
    for index in 1..=count {
        match probe_once(addr, secret, dc).await {
            Ok(elapsed) => {
                let millis = elapsed.as_secs_f64() * 1000.0;
                println!("{index:02} OK {millis:.1} ms");
                samples.push(millis);
            }
            Err(error) => {
                println!("{index:02} FAIL {error}");
                failures.push(error);
            }
        }
        sleep(Duration::from_millis(150)).await;
    }

    samples.sort_by(f64::total_cmp);
    if samples.is_empty() {
        println!("SUMMARY dc={dc} ok=0/{count}");
        std::process::exit(1);
    }
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let p50 = samples[(samples.len() - 1) * 50 / 100];
    let p95 = samples[(samples.len() - 1) * 95 / 100];
    println!(
        "SUMMARY dc={dc} ok={}/{} min={:.1} mean={mean:.1} p50={p50:.1} p95={p95:.1} max={:.1} ms",
        samples.len(),
        count,
        samples[0],
        samples[samples.len() - 1]
    );
    if !failures.is_empty() {
        std::process::exit(1);
    }
}
