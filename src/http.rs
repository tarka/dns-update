/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
*/

use std::{fmt::Debug, future::Future, sync::Arc, time::Duration};

use async_lock::OnceCell;
use cfg_if::cfg_if;
use http::{request::Builder, HeaderMap, HeaderValue};
use http_body_reader::ResponseExt;
use hyper::{
    body::Incoming,
    client::conn::http1,
    header::{CONTENT_TYPE, HOST},
    Method, Response, Uri,
};
use rustls::{
    crypto::aws_lc_rs,
    pki_types::ServerName,
    ClientConfig,
    RootCertStore
};
use serde::{de::DeserializeOwned, Serialize};

use crate::Error;

static ROOT_STORE: OnceCell<Arc<RootCertStore>> = OnceCell::new();

async fn load_system_certs() -> Arc<RootCertStore> {
    ROOT_STORE.get_or_init(|| async {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(root_store)
    }).await.clone()
}

cfg_if! {
    if #[cfg(feature = "smol")] {
        use smol::net::TcpStream;  // Could also be async_net
        use futures_rustls::TlsConnector;
        use smol_hyper::rt::FuturesIo as HyperIo;

    } else if #[cfg(feature = "tokio")] {
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use hyper_util::rt::tokio::TokioIo as HyperIo;

    } else {
        compile_error!("Either smol or tokio feature must be enabled");
    }
}

fn spawn<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) {
    cfg_if! {
        if #[cfg(feature = "smol")] {
            smol::spawn(future)
                .detach();

        } else if #[cfg(feature = "tokio")] {
            tokio::spawn(future);
        }
    }

    // NOTE: This also works, and could be a fallback for other runtimes?
    //
    // let _join = thread::spawn(|| {
    //     pollster::block_on(future);
    // });
}

async fn request(
    method: Method,
    url: &String,
    body: Option<String>,
    headers: HeaderMap,
) -> crate::Result<Response<Incoming>>
{
    let uri: Uri = url.parse().unwrap();

    let host = uri.host()
        .ok_or(Error::Url(format!("URL: {:?}", uri)))?
        .to_owned();

    let mut rb = Builder::new()
        .method(method)
        .uri(uri)
        .header(HOST, &host);
    let rheaders = rb.headers_mut()
        .ok_or(Error::Client("Failed to retrieve HTTP builder headers".to_string()))?;
    for (k, v) in headers {
        if let Some(k) = k {
            println! ("Insert {k} {v:?}");
            rheaders.insert(k, v);
        }
    }
    let req = if let Some(body) = body {
        rb.body(body)
    } else {
        rb.body("".to_string())
    }.map_err(|e| Error::Parse(format!("Error attaching body: {:?}", e)))?;


    let stream = TcpStream::connect((host.clone(), 443)).await
        .map_err(|e| Error::Client(format!("Client error: {:?}", e)))?;

    let cert_store = load_system_certs();
    let tlsdomain = ServerName::try_from(host)
        .map_err(|e| Error::Client(format!("Client error: {:?}", e)))?;
    let crypto = aws_lc_rs::default_provider();
    let tlsconf = ClientConfig::builder_with_provider(crypto.into())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Client(format!("Client error: {:?}", e)))?
        .with_root_certificates(cert_store.await)
        .with_no_client_auth();
    let tlsconn = TlsConnector::from(Arc::new(tlsconf));
    let tlsstream = tlsconn.connect(tlsdomain, stream).await
        .map_err(|e| Error::Client(format!("Client error: {:?}", e)))?;

    let (mut sender, conn) = http1::handshake(HyperIo::new(tlsstream)).await
        .map_err(|e| Error::Client(format!("Client error: {:?}", e)))?;

    spawn(async move {
        if let Err(e) = conn.await {
            // FIXME: Logging?
            eprintln!("Connection failed: {:?}", e);
        }
    });

    let res = sender.send_request(req).await
        .map_err(|e| Error::Client(format!("Client error: {:?}", e)))?;

    Ok(res)
}


async fn text(response: Response<Incoming>) -> crate::Result<String>
{
    response.body_reader().utf8().await
        .map_err(|err| {
            Error::Api(format!("Failed to read error body {err:?}"))
        })
}

#[derive(Debug, Clone)]
pub struct HttpClientBuilder {
    timeout: Duration,
    headers: HeaderMap<HeaderValue>,
}

#[derive(Debug, Default, Clone)]
pub struct HttpClient {
    method: Method,
    timeout: Duration,
    url: String,
    headers: HeaderMap<HeaderValue>,
    body: Option<String>,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        Self {
            timeout: Duration::from_secs(30),
            headers,
        }
    }
}

impl HttpClientBuilder {
    pub fn build(&self, method: Method, url: impl Into<String>) -> HttpClient {
        HttpClient {
            method,
            url: url.into(),
            headers: self.headers.clone(),
            body: None,
            timeout: self.timeout,
        }
    }

    pub fn get(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::GET, url)
    }

    pub fn post(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::POST, url)
    }

    pub fn put(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::PUT, url)
    }

    pub fn delete(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::DELETE, url)
    }

    pub fn patch(&self, url: impl Into<String>) -> HttpClient {
        self.build(Method::PATCH, url)
    }

    pub fn with_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.append(name, value);
        }
        self
    }

    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        if let Some(timeout) = timeout {
            self.timeout = timeout;
        }
        self
    }
}

impl HttpClient {
    pub fn with_header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.append(name, value);
        }
        self
    }

    pub fn with_body<B: Serialize>(mut self, body: B) -> crate::Result<Self> {
        match serde_json::to_string(&body) {
            Ok(body) => {
                self.body = Some(body);
                Ok(self)
            }
            Err(err) => Err(Error::Serialize(format!(
                "Failed to serialize request: {err}"
            ))),
        }
    }

    pub fn with_raw_body(mut self, body: String) -> Self {
        self.body = Some(body);
        self
    }

    pub async fn send<T>(self) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.send_raw().await?;
        serde_json::from_slice::<T>(response.as_bytes())
            .map_err(|err| Error::Serialize(format!("Failed to deserialize response: {err}")))
    }

    pub async fn send_raw(self) -> crate::Result<String> {

        let response = request(self.method,
                               &self.url,
                               self.body,
                               self.headers).await?;

        match response.status().as_u16() {
            204 => serde_json::from_str("{}")
                .map_err(|err| Error::Serialize(format!("Failed to create empty response: {err}"))),
            200..=299 => response.body_reader().utf8().await.map_err(|err| {
                Error::Api(format!("Failed to read response from {}: {err}", self.url))
            }),
            400 => {
                let text = text(response).await?;
                Err(Error::Api(format!("BadRequest {}", text)))
            }
            401 => Err(Error::Unauthorized),
            404 => Err(Error::NotFound),
            code => {
                let body = text(response).await?;
                Err(Error::Api(format!("Invalid HTTP response code {code}: {body}")))
            },
        }
    }

    pub async fn send_with_retry<T>(self, max_retries: u32) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        let mut attempts = 0;
        loop {
            let response = request(self.method.clone(),
                                   &self.url,
                                   self.body.clone(),
                                   self.headers.clone()).await?;

            return match response.status().as_u16() {
                204 => serde_json::from_str("{}").map_err(|err| {
                    Error::Serialize(format!("Failed to create empty response: {err}"))
                }),
                200..=299 => {
                    let text = text(response).await?;
                    serde_json::from_str(&text).map_err(|err| {
                        Error::Serialize(format!("Failed to deserialize response: {err}"))
                    })
                }
                429 if attempts < max_retries => {
                    if let Some(retry_after) = response.headers().get("retry-after") {
                        if let Ok(seconds) = retry_after.to_str().unwrap_or("0").parse::<u64>() {
                            tokio::time::sleep(Duration::from_secs(seconds)).await;
                            attempts += 1;
                            continue;
                        }
                    }
                    Err(Error::Api("Rate limit exceeded".to_string()))
                }
                400 => {
                    let text = text(response).await?;
                    Err(Error::Api(format!("BadRequest {}", text)))
                }
                401 => Err(Error::Unauthorized),
                404 => Err(Error::NotFound),
                code => {
                    let body = text(response).await?;
                    Err(Error::Api(format!("Invalid HTTP response code {code}: {body}")))
                },
            };
        }
    }
}
