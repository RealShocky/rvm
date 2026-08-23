//! Minimal TLS client for the hosted context and MCP routes.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rustls::pki_types::{CertificateDer, ServerName};
use std::env;
use std::fs;
use std::io::{self, Write as _};
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != 7 {
        return Err("usage: rvm-context-cli HOST PORT CA_PEM TOKEN_FILE ROUTE JSON_FILE".into());
    }
    let host = &arguments[1];
    let port = &arguments[2];
    let route = validate_route(&arguments[5])?;
    let body = fs::read(&arguments[6])?;
    if body.len() > 24 * 1024 * 1024 {
        return Err("request body exceeds 24 MiB".into());
    }
    let token_file = fs::read(&arguments[4])?;
    let token = trim_ascii(&token_file);
    if token.len() < 32 {
        return Err("token file is too short".into());
    }

    let mut roots = rustls::RootCertStore::empty();
    let certificates = pem_blocks(&fs::read(&arguments[3])?, "CERTIFICATE")?;
    if certificates.is_empty() {
        return Err("CA file contains no certificates".into());
    }
    for certificate in certificates {
        roots.add(CertificateDer::from(certificate))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(format!("{host}:{port}")).await?;
    let server_name = ServerName::try_from(host.clone())?;
    let mut stream = connector.connect(server_name, stream).await?;

    let mut request = Vec::new();
    write!(
        request,
        "POST {route} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer "
    )?;
    request.extend_from_slice(token);
    write!(
        request,
        "\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    request.extend_from_slice(&body);
    stream.write_all(&request).await?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(count) => {
                if response.len().saturating_add(count) > MAX_RESPONSE_BYTES {
                    return Err("response exceeds 32 MiB".into());
                }
                response.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && !response.is_empty() => {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("invalid HTTP response")?;
    let header = std::str::from_utf8(&response[..split])?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or("invalid HTTP status")?;
    io::stdout().write_all(&response[split + 4..])?;
    io::stdout().write_all(b"\n")?;
    if status >= 400 {
        std::process::exit(1);
    }
    Ok(())
}

fn validate_route(value: &str) -> Result<&str, Box<dyn std::error::Error>> {
    if value == "/mcp" || value.starts_with("/v1/") && !value.contains(['?', '#']) {
        Ok(value)
    } else {
        Err("route must be /mcp or a plain /v1/* path".into())
    }
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
        blocks.push(BASE64.decode(encoded.split_ascii_whitespace().collect::<String>())?);
        remainder = after_end;
    }
    Ok(blocks)
}
