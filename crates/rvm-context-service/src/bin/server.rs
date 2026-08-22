//! TLS-only hosted `ruv://` HTTP and MCP gateway.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rvm_context::{ContextAuthority, ContextRuntime, ContextScope, ContextViewMask, RuvUri};
use rvm_context_service::{
    ContextGateway, HashEmbedder, LocalKeyProvider, NoopPurgeSink, PersistentContextResolver,
    ResolverOptions,
};
use rvm_types::{CapRights, PartitionId};
use std::convert::Infallible;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const MAX_BODY_BYTES: usize = 24 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 128;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
type Gateway = ContextGateway<1024, 1024, 4096>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bind: SocketAddr = required("RVM_CONTEXT_BIND")?.parse()?;
    let scope = RuvUri::parse(&required("RVM_CONTEXT_SCOPE")?)?;
    let actor = PartitionId::new(required("RVM_CONTEXT_ACTOR")?.parse()?);
    let root = required("RVM_CONTEXT_ROOT")?;
    let token = load_token(&required("RVM_CONTEXT_TOKEN_FILE")?)?;
    let key = parse_hex_key(&required("RVM_CONTEXT_DEV_KEK_HEX")?)?;
    if env::var("RVM_CONTEXT_ALLOW_LOCAL_KEK").as_deref() != Ok("1") {
        return Err("local development KEK requires RVM_CONTEXT_ALLOW_LOCAL_KEK=1".into());
    }

    let resolver = PersistentContextResolver::open(
        root,
        ResolverOptions::default(),
        Arc::new(LocalKeyProvider::new("gateway-local-kek", key)?),
        Arc::new(HashEmbedder::new(384)?),
        Arc::new(NoopPurgeSink),
    )?;
    let mut authority = ContextAuthority::<1024, 1024>::with_defaults();
    let mut rights = CapRights::READ | CapRights::PROVE;
    if env::var("RVM_CONTEXT_ALLOW_WRITES").as_deref() == Ok("1") {
        rights |= CapRights::WRITE;
    }
    let capability = authority
        .issue_root(
            ContextScope::from_uri(&scope, ContextViewMask::ALL),
            rights,
            actor,
            PartitionId::HYPERVISOR,
        )
        .map_err(|error| format!("context capability configuration failed: {error}"))?;
    let runtime = ContextRuntime::new(actor, authority, resolver);
    let gateway = Arc::new(ContextGateway::new(runtime, capability));
    let tls = TlsAcceptor::from(Arc::new(tls_config(
        &required("RVM_CONTEXT_TLS_CERT")?,
        &required("RVM_CONTEXT_TLS_KEY")?,
    )?));
    let listener = TcpListener::bind(bind).await?;
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (stream, _) = listener.accept().await?;
        let permit = Arc::clone(&semaphore).acquire_owned().await?;
        let tls = tls.clone();
        let gateway = Arc::clone(&gateway);
        let token = Arc::clone(&token);
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(stream)) = timeout(REQUEST_TIMEOUT, tls.accept(stream)).await else {
                return;
            };
            let io = TokioIo::new(stream);
            let service =
                service_fn(move |request| serve(request, Arc::clone(&gateway), Arc::clone(&token)));
            let _ = timeout(
                REQUEST_TIMEOUT,
                http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(io, service),
            )
            .await;
        });
    }
}

async fn serve(
    request: Request<Incoming>,
    gateway: Arc<Gateway>,
    token: Arc<Vec<u8>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != Method::POST {
        return Ok(response(
            StatusCode::METHOD_NOT_ALLOWED,
            br#"{"error":{"code":"method_not_allowed"}}"#,
        ));
    }
    let authenticated = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|candidate| constant_time_eq(candidate.as_bytes(), &token));
    if !authenticated {
        return Ok(response(
            StatusCode::UNAUTHORIZED,
            br#"{"error":{"code":"unauthorized"}}"#,
        ));
    }
    let route = request.uri().path().to_owned();
    let body = match bounded_body(request.into_body()).await {
        Ok(body) => body,
        Err(status) => return Ok(response(status, br#"{"error":{"code":"invalid_body"}}"#)),
    };
    let dispatched = if route == "/mcp" {
        gateway.dispatch_mcp(&body)
    } else {
        gateway.dispatch(&route, &body)
    };
    let status =
        StatusCode::from_u16(dispatched.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Ok(response(status, dispatched.body()))
}

async fn bounded_body(mut body: Incoming) -> Result<Bytes, StatusCode> {
    let mut output = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(data) = frame.data_ref() {
            if output.len().saturating_add(data.len()) > MAX_BODY_BYTES {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            output.extend_from_slice(data);
        }
    }
    Ok(output.freeze())
}

fn response(status: StatusCode, body: &[u8]) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::copy_from_slice(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        hyper::header::HeaderValue::from_static("nosniff"),
    );
    response
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("missing required environment variable {name}").into())
}

fn load_token(path: &str) -> Result<Arc<Vec<u8>>, Box<dyn std::error::Error>> {
    let token = fs::read(path)?;
    let token = trim_ascii(&token).to_vec();
    if token.len() < 32 || token.len() > 4096 {
        return Err("gateway token must contain 32 through 4096 bytes".into());
    }
    Ok(Arc::new(token))
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

fn parse_hex_key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("development KEK must be exactly 64 hexadecimal characters".into());
    }
    let mut key = [0u8; 32];
    for (index, output) in key.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(key)
}

fn tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let certificates = pem_blocks(&fs::read(cert_path)?, "CERTIFICATE")?
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    if certificates.is_empty() {
        return Err("TLS certificate file contains no certificates".into());
    }
    let key_bytes = fs::read(key_path)?;
    let key = if let Some(value) = pem_blocks(&key_bytes, "PRIVATE KEY")?.into_iter().next() {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(value))
    } else if let Some(value) = pem_blocks(&key_bytes, "RSA PRIVATE KEY")?
        .into_iter()
        .next()
    {
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(value))
    } else if let Some(value) = pem_blocks(&key_bytes, "EC PRIVATE KEY")?.into_iter().next() {
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(value))
    } else {
        return Err("TLS key file contains no supported private key".into());
    };
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?)
}

fn pem_blocks(data: &[u8], label: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let text = std::str::from_utf8(data)?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut remainder = text;
    while let Some((_, after_begin)) = remainder.split_once(&begin) {
        let Some((encoded, after_end)) = after_begin.split_once(&end) else {
            return Err(format!("unterminated PEM {label} block").into());
        };
        let compact = encoded.split_ascii_whitespace().collect::<String>();
        blocks.push(BASE64.decode(compact.as_bytes())?);
        remainder = after_end;
    }
    Ok(blocks)
}
