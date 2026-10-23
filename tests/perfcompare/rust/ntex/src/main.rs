use std::{env, io, path::PathBuf, process, sync::OnceLock};

use ntex::SharedCfg;
use ntex::http::header::{ACCEPT_LANGUAGE, HeaderValue, USER_AGENT};
use ntex::http::{HttpMessage, HttpService};
use ntex::util::{ByteString, Bytes};
use ntex::web::{self, App, HttpRequest, HttpResponse, HttpServer, middleware::Compress, types::Path, ws};
use ntex_cors::Cors;
use ntex_files::Files;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Serialize;

const EXIT_UNSUPPORTED: i32 = 64;
const EXIT_USAGE: i32 = 2;
const HELLO: &[u8] = b"Hello, World!";
const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog. ";
const SIZE_64K: usize = 65536;
const SIZE_1M: usize = 1048576;
const SIZE_16K: usize = 16384;
const STATIC_MOUNT: &str = "/static";
const TEXT_PLAIN: HeaderValue = HeaderValue::from_static("text/plain");
const OCTET_STREAM: HeaderValue = HeaderValue::from_static("application/octet-stream");

struct Bodies {
    bytes_64k: Bytes,
    bytes_1m: Bytes,
    text_16k: Bytes,
}

static BODIES: OnceLock<Bodies> = OnceLock::new();

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
    Bytes::from(pattern.iter().copied().cycle().take(len).collect::<Vec<u8>>())
}

fn bodies() -> &'static Bodies {
    BODIES.get_or_init(|| Bodies {
        bytes_64k: repeat_to(b"x", SIZE_64K),
        bytes_1m: repeat_to(b"x", SIZE_1M),
        text_16k: repeat_to(FOX, SIZE_16K),
    })
}

fn typed(body: Bytes, content_type: HeaderValue) -> HttpResponse {
    HttpResponse::Ok().content_type(content_type).body(body)
}

async fn plaintext() -> HttpResponse {
    typed(Bytes::from_static(HELLO), TEXT_PLAIN)
}

async fn json() -> HttpResponse {
    HttpResponse::Ok().json(&HelloMessage { message: "Hello, World!" })
}

async fn user(id: Path<String>) -> HttpResponse {
    typed(Bytes::from(id.into_inner()), TEXT_PLAIN)
}

async fn echo(body: Bytes) -> HttpResponse {
    typed(Bytes::from(body.len().to_string()), TEXT_PLAIN)
}

async fn bytes_64k() -> HttpResponse {
    typed(bodies().bytes_64k.clone(), OCTET_STREAM)
}

async fn bytes_1m() -> HttpResponse {
    typed(bodies().bytes_1m.clone(), OCTET_STREAM)
}

async fn text_16k() -> HttpResponse {
    typed(bodies().text_16k.clone(), TEXT_PLAIN)
}

async fn browser(req: HttpRequest) -> HttpResponse {
    let header_bytes = |name| req.headers().get(name).map(HeaderValue::as_bytes).unwrap_or_default();
    let user_agent = header_bytes(&USER_AGENT);
    let accept_language = header_bytes(&ACCEPT_LANGUAGE);
    let sid = req.cookie("sid");
    let sid = sid.as_ref().map(|c| c.value()).unwrap_or_default();
    let mut out = Vec::with_capacity(user_agent.len() + accept_language.len() + sid.len() + 2);
    out.extend_from_slice(user_agent);
    out.push(b'|');
    out.extend_from_slice(accept_language);
    out.push(b'|');
    out.extend_from_slice(sid.as_bytes());
    typed(Bytes::from(out), TEXT_PLAIN)
}

async fn mw() -> HttpResponse {
    typed(Bytes::from_static(b"ok"), TEXT_PLAIN)
}

async fn ws_frame(frame: ws::Frame) -> Result<Option<ws::Message>, io::Error> {
    Ok(match frame {
        ws::Frame::Text(text) => Some(match ByteString::try_from(text) {
            Ok(text) => ws::Message::Text(text),
            Err(_) => ws::Message::Close(Some(ws::CloseCode::Protocol.into())),
        }),
        ws::Frame::Binary(bin) => Some(ws::Message::Binary(bin)),
        ws::Frame::Continuation(item) => Some(ws::Message::Continuation(item)),
        ws::Frame::Ping(payload) => Some(ws::Message::Pong(payload)),
        ws::Frame::Pong(_) => None,
        ws::Frame::Close(reason) => Some(ws::Message::Close(reason)),
    })
}

async fn ws_upgrade(req: HttpRequest) {
    let _ = ws::start(&req, None, ws_frame).await;
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

#[ntex::main]
async fn main() -> io::Result<()> {
    let args = parse_args();

    if args.mode == "proxy" {
        unsupported(
            "proxy",
            "ntex 4.3.0 ships no reverse-proxy service or middleware, only an HTTP client (checked ntex-4.3.0/src/web/, src/web/middleware/ and the ntex-rs ntex-extras crates ntex-files/ntex-cors)",
        );
    }
    if args.mode != "app" {
        eprintln!("unknown mode {}", args.mode);
        process::exit(EXIT_USAGE);
    }

    bodies();
    let static_dir = args.static_dir.clone();
    let make_app = move || {
        App::new()
            .route("/", web::get().to(plaintext))
            .route("/plaintext", web::get().to(plaintext))
            .route("/json", web::get().to(json))
            .route("/user/{id}", web::get().to(user))
            .route("/echo", web::post().to(echo))
            .route("/bytes/64k", web::get().to(bytes_64k))
            .route("/bytes/1m", web::get().to(bytes_1m))
            .service(Files::new(STATIC_MOUNT, static_dir.clone()))
            .service(
                web::resource("/text16k")
                    .middleware(Compress::default())
                    .route(web::get().to(text_16k)),
            )
            .route("/browser", web::get().to(browser))
            .service(
                web::resource("/mw")
                    .middleware(Cors::new().send_wildcard().build())
                    .route(web::get().to(mw)),
            )
            .route("/ws", web::get().to(ws_upgrade))
    };

    let server = match args.proto.as_str() {
        "h1" => HttpServer::new(async move |_| make_app())
            .bind(&args.addr, SharedCfg::default())?
            .run(),
        "tls" | "h2" => {
            let tls = load_tls(&args)?;
            HttpServer::new(async move |_| make_app())
                .bind_rustls(&args.addr, &tls, SharedCfg::default())?
                .run()
        }
        "h2c" => ntex::server::build()
            .bind("perf-ntex-h2c", &args.addr, SharedCfg::default(), async move |_| {
                HttpService::h2(make_app())
            })?
            .run(),
        other => unsupported(other, "unknown protocol"),
    };

    println!("READY");
    server.await
}
