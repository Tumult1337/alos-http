use std::{env, io, path::PathBuf, process};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use xitca_web::{
    App,
    bytes::Bytes,
    handler::{
        cookie::CookieJar,
        handler_service,
        header::{self, HeaderRef},
        json::Json,
        params::Params,
        state::StateRef,
        websocket::{Message, WebSocket},
    },
    http::header::{CONTENT_TYPE, HeaderName, HeaderValue},
    middleware::{compress::Compress, eraser::TypeEraser, rate_limit::RateLimit, tower_http_compat::TowerHttpCompat},
    route::{get, post},
    service::ServiceExt,
    service::file::ServeDir,
};

const EXIT_UNSUPPORTED: i32 = 64;
const EXIT_USAGE: i32 = 2;
const HELLO: &[u8] = b"Hello, World!";
const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog. ";
const SIZE_64K: usize = 65536;
const SIZE_1M: usize = 1048576;
const SIZE_16K: usize = 16384;
const RATE_LIMIT_PER_SECOND: u32 = 1_000_000_000;
const STATIC_MOUNT: &str = "/static";
const STATIC_DIR_NAME: &str = "static";
const TEXT_PLAIN: HeaderValue = HeaderValue::from_static("text/plain");
const OCTET_STREAM: HeaderValue = HeaderValue::from_static("application/octet-stream");

type Typed = ((HeaderName, HeaderValue), Bytes);

#[derive(Clone)]
struct Bodies {
    bytes_64k: Bytes,
    bytes_1m: Bytes,
    text_16k: Bytes,
}

#[derive(Serialize)]
struct HelloMessage {
    message: &'static str,
}

struct Args {
    proto: String,
    mode: String,
    addr: String,
    cert: PathBuf,
    key: PathBuf,
    static_dir: PathBuf,
}

fn parse_args() -> Args {
    let mut args = Args {
        proto: "h1".into(),
        mode: "app".into(),
        addr: "127.0.0.1:18080".into(),
        cert: "/root/alos-perf/harness/certs/cert.pem".into(),
        key: "/root/alos-perf/harness/certs/key.pem".into(),
        static_dir: "/root/alos-perf/harness/static".into(),
    };
    let mut it = env::args().skip(1);
    while let Some(flag) = it.next() {
        let Some(value) = it.next() else {
            eprintln!("missing value for {flag}");
            process::exit(EXIT_USAGE);
        };
        match flag.as_str() {
            "-proto" => args.proto = value,
            "-mode" => args.mode = value,
            "-addr" => args.addr = value,
            "-cert" => args.cert = value.into(),
            "-key" => args.key = value.into(),
            "-static" => args.static_dir = value.into(),
            "-origin" => {}
            _ => {
                eprintln!("unknown flag {flag}");
                process::exit(EXIT_USAGE);
            }
        }
    }
    args
}

fn unsupported(what: &str, reason: &str) -> ! {
    println!("UNSUPPORTED {what}: {reason}");
    process::exit(EXIT_UNSUPPORTED);
}

fn repeat_to(pattern: &[u8], len: usize) -> Bytes {
    pattern.iter().copied().cycle().take(len).collect::<Vec<u8>>().into()
}

fn typed(body: Bytes, content_type: HeaderValue) -> Typed {
    ((CONTENT_TYPE, content_type), body)
}

async fn plaintext() -> Typed {
    typed(Bytes::from_static(HELLO), TEXT_PLAIN)
}

async fn json() -> Json<HelloMessage> {
    Json(HelloMessage { message: "Hello, World!" })
}

async fn user(Params(id): Params<String>) -> Typed {
    typed(Bytes::from(id), TEXT_PLAIN)
}

async fn echo(body: Bytes) -> Typed {
    typed(Bytes::from(body.len().to_string()), TEXT_PLAIN)
}

async fn bytes_64k(StateRef(bodies): StateRef<'_, Bodies>) -> Typed {
    typed(bodies.bytes_64k.clone(), OCTET_STREAM)
}

async fn bytes_1m(StateRef(bodies): StateRef<'_, Bodies>) -> Typed {
    typed(bodies.bytes_1m.clone(), OCTET_STREAM)
}

async fn text_16k(StateRef(bodies): StateRef<'_, Bodies>) -> Typed {
    typed(bodies.text_16k.clone(), TEXT_PLAIN)
}

async fn browser(
    user_agent: HeaderRef<'_, { header::USER_AGENT }>,
    accept_language: HeaderRef<'_, { header::ACCEPT_LANGUAGE }>,
    jar: CookieJar,
) -> Typed {
    let sid = jar.get("sid").map(|c| c.value()).unwrap_or_default();
    let mut out = Vec::with_capacity(user_agent.len() + accept_language.len() + sid.len() + 2);
    out.extend_from_slice(user_agent.as_bytes());
    out.push(b'|');
    out.extend_from_slice(accept_language.as_bytes());
    out.push(b'|');
    out.extend_from_slice(sid.as_bytes());
    typed(Bytes::from(out), TEXT_PLAIN)
}

async fn mw() -> Typed {
    typed(Bytes::from_static(b"ok"), TEXT_PLAIN)
}

async fn ws(mut ws: WebSocket) -> WebSocket {
    ws.on_msg(|tx, msg| {
        Box::pin(async move {
            let _ = match msg {
                Message::Text(txt) => tx.text(txt.into_inner()).await,
                Message::Binary(bin) => tx.binary(bin).await,
                Message::Continuation(item) => tx.continuation(item).await,
            };
        })
    });
    ws
}

fn load_tls(args: &Args) -> io::Result<rustls::ServerConfig> {
    let certs = CertificateDer::pem_file_iter(&args.cert)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_file(&args.key).map_err(io::Error::other)?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)
}

fn static_root(static_dir: &PathBuf) -> PathBuf {
    let parent = static_dir.parent().filter(|_| static_dir.file_name().is_some_and(|n| n == STATIC_DIR_NAME));
    match parent {
        Some(parent) => parent.to_path_buf(),
        None => {
            eprintln!("-static directory must be named {STATIC_DIR_NAME}");
            process::exit(EXIT_USAGE);
        }
    }
}

fn main() -> io::Result<()> {
    let args = parse_args();

    if args.mode == "proxy" {
        unsupported(
            "proxy",
            "xitca-web 0.8.3 ships no reverse-proxy service or middleware (checked xitca-web-0.8.3/src/{service,middleware}/ and the HFQR/xitca-web examples/)",
        );
    }
    if args.mode != "app" {
        eprintln!("unknown mode {}", args.mode);
        process::exit(EXIT_USAGE);
    }

    let bodies = Bodies {
        bytes_64k: repeat_to(b"x", SIZE_64K),
        bytes_1m: repeat_to(b"x", SIZE_1M),
        text_16k: repeat_to(FOX, SIZE_16K),
    };

    let server = App::new()
        .with_state(bodies)
        .at("/", get(handler_service(plaintext)))
        .at("/plaintext", get(handler_service(plaintext)))
        .at("/json", get(handler_service(json)))
        .at("/user/{id}", get(handler_service(user)))
        .at("/echo", post(handler_service(echo)))
        .at("/bytes/64k", get(handler_service(bytes_64k)))
        .at("/bytes/1m", get(handler_service(bytes_1m)))
        .at(STATIC_MOUNT, ServeDir::new(static_root(&args.static_dir)))
        .at(
            "/text16k",
            get(handler_service(text_16k)
                .enclosed(Compress)
                .enclosed(TypeEraser::response_body())),
        )
        .at("/browser", get(handler_service(browser)))
        .at(
            "/mw",
            get(handler_service(mw)
                .enclosed(RateLimit::per_second(RATE_LIMIT_PER_SECOND))
                .enclosed(TowerHttpCompat::new(CorsLayer::new().allow_origin(Any)))
                .enclosed(TypeEraser::response_body())),
        )
        .at("/ws", get(handler_service(ws)))
        .serve();

    let server = match args.proto.as_str() {
        "h1" => server.bind(&args.addr)?,
        "h2c" => server.h2c_prior_knowledge().bind(&args.addr)?,
        "tls" | "h2" => server.bind_rustls(&args.addr, load_tls(&args)?)?,
        other => unsupported(other, "unknown protocol"),
    };

    let running = server.run();
    println!("READY");
    running.wait()
}
