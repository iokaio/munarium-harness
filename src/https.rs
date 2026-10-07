// SPDX-License-Identifier: Apache-2.0
//! Single-attempt mutually authenticated decision transport. No execution methods.
use crate::decision::{Error, Proposal, Transport};
use reqwest::{Certificate, Identity, Url, blocking::Client};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};

/// Certificate-validating HTTPS transport; the callback supplies current original evidence.
pub struct HttpsTransport<F: FnMut() -> Result<Vec<String>, Error>> {
    client: Client,
    endpoint: Url,
    chain: F,
}
impl<F: FnMut() -> Result<Vec<String>, Error>> HttpsTransport<F> {
    /// Build with PEM client certificate/key and enrolled CA. Redirects and proxies are disabled.
    pub fn new(
        endpoint: &str,
        identity_pem: &[u8],
        ca_pem: &[u8],
        chain: F,
    ) -> Result<Self, Error> {
        let mut endpoint = Url::parse(endpoint).map_err(|_| Error::InvalidInput)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::InvalidInput);
        }
        endpoint.set_path("/v1/decisions");
        let client = Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(20))
            .identity(Identity::from_pem(identity_pem).map_err(|_| Error::InvalidInput)?)
            .add_root_certificate(Certificate::from_pem(ca_pem).map_err(|_| Error::InvalidInput)?)
            .build()
            .map_err(|_| Error::InvalidInput)?;
        Ok(Self {
            client,
            endpoint,
            chain,
        })
    }
    fn call(&mut self, tenant: &str, action: Value) -> Result<Value, Error> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&json!({"tenant":tenant,"chain":(self.chain)()?,"action":action}))
            .send()
            .map_err(|_| Error::Unresolved)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unresolved);
        }
        let mut raw = Vec::new();
        response
            .take(65537)
            .read_to_end(&mut raw)
            .map_err(|_| Error::Unresolved)?;
        let raw = crate::decision::canonical(&raw)?;
        serde_json::from_slice(&raw).map_err(|_| Error::InvalidInput)
    }
    /// Replay already recorded inputs without writing another proposal or dispatching.
    pub fn replay(&mut self, tenant: &str, operation_id: &str) -> Result<Value, Error> {
        self.call(
            tenant,
            json!({"operation":"replay","operation_id":operation_id}),
        )
    }
}
impl<F: FnMut() -> Result<Vec<String>, Error>> Transport for HttpsTransport<F> {
    fn submit(&mut self, p: &Proposal) -> Result<Value, Error> {
        self.call(p.tenant(),json!({"operation":"submit","request":std::str::from_utf8(p.bytes()).map_err(|_|Error::InvalidInput)?}))
    }
    fn lookup(&mut self, tenant: &str, operation_id: &str) -> Result<Value, Error> {
        self.call(
            tenant,
            json!({"operation":"lookup","operation_id":operation_id}),
        )
    }
}
