//! Shared JSON dispatcher for HTTPS, MCP, and local CLI transports.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rvm_context::{
    AliasSnapshot, CapabilityHandle, ContextError, ContextOperation, ContextRequest,
    ContextRuntime, ResolvedContext, Revision, RuvUri,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Mutex;

use crate::PersistentContextResolver;

/// A transport-independent JSON response with an HTTP-compatible status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayResponse {
    status: u16,
    body: Vec<u8>,
}

impl GatewayResponse {
    /// HTTP-compatible status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// UTF-8 JSON response bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Actor-bound facade used by HTTPS, MCP, and CLI adapters.
///
/// Each instance owns exactly one RVM runtime and capability handle. External
/// authentication must select the correct instance before calling it; request
/// JSON cannot select an actor or substitute a capability.
pub struct ContextGateway<const CAPABILITIES: usize, const GRANTS: usize, const WITNESSES: usize> {
    runtime: Mutex<ContextRuntime<PersistentContextResolver, CAPABILITIES, GRANTS, WITNESSES>>,
    capability: CapabilityHandle,
}

impl<const CAPABILITIES: usize, const GRANTS: usize, const WITNESSES: usize>
    ContextGateway<CAPABILITIES, GRANTS, WITNESSES>
{
    /// Bind a gateway session to one trusted runtime and one live capability.
    #[must_use]
    pub const fn new(
        runtime: ContextRuntime<PersistentContextResolver, CAPABILITIES, GRANTS, WITNESSES>,
        capability: CapabilityHandle,
    ) -> Self {
        Self {
            runtime: Mutex::new(runtime),
            capability,
        }
    }

    /// Dispatch one canonical v1 API route.
    ///
    /// Supported routes are `/v1/resolve`, `/v1/list`, `/v1/tree`,
    /// `/v1/read`, `/v1/search`, `/v1/history`, `/v1/verify`, `/v1/put`,
    /// `/v1/cas`, and `/v1/forget`.
    #[must_use]
    pub fn dispatch(&self, route: &str, body: &[u8]) -> GatewayResponse {
        let Ok(mut runtime) = self.runtime.lock() else {
            return error_response(503, "unavailable", "context runtime unavailable");
        };
        match dispatch_api(&mut runtime, self.capability, route, body) {
            Ok(value) => json_response(200, &value),
            Err(error) => context_error_response(error),
        }
    }

    /// Dispatch an MCP 2025-03-26 JSON-RPC request.
    ///
    /// Tool calls use the same route dispatcher as HTTPS, preserving the
    /// canonical `ruv://` string and identical authorization ordering.
    #[must_use]
    pub fn dispatch_mcp(&self, body: &[u8]) -> GatewayResponse {
        let request: McpRequest = match serde_json::from_slice(body) {
            Ok(request) => request,
            Err(_) => return mcp_error(&Value::Null, -32700, "invalid JSON"),
        };
        if request.jsonrpc != "2.0" {
            return mcp_error(&request.id, -32600, "unsupported JSON-RPC version");
        }
        match request.method.as_str() {
            "initialize" => json_response(
                200,
                &json!({
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "rvm-context", "version": "1"}
                    }
                }),
            ),
            "tools/list" => json_response(
                200,
                &json!({
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "result": {"tools": mcp_tools()}
                }),
            ),
            "tools/call" => {
                let Some(params) = request.params else {
                    return mcp_error(&request.id, -32602, "missing tool parameters");
                };
                let call: McpToolCall = match serde_json::from_value(params) {
                    Ok(call) => call,
                    Err(_) => {
                        return mcp_error(&request.id, -32602, "invalid tool parameters");
                    }
                };
                let Some(route) = tool_route(&call.name) else {
                    return mcp_error(&request.id, -32601, "unknown context tool");
                };
                let Ok(arguments) = serde_json::to_vec(&call.arguments) else {
                    return mcp_error(&request.id, -32603, "tool encoding failed");
                };
                let response = self.dispatch(route, &arguments);
                let value: Value = serde_json::from_slice(response.body())
                    .unwrap_or_else(|_| json!({"error": {"code": "internal"}}));
                json_response(
                    200,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": request.id,
                        "result": {
                            "content": [{"type": "text", "text": value.to_string()}],
                            "structuredContent": value,
                            "isError": response.status() >= 400
                        }
                    }),
                )
            }
            _ => mcp_error(&request.id, -32601, "method not found"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UriInput {
    uri: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnumerationInput {
    uri: String,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    uri: String,
    query: String,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutInput {
    uri: String,
    rvf_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotInput {
    alias: String,
    revision: String,
    generation: u64,
    tombstone: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CasInput {
    uri: String,
    expected: Option<SnapshotInput>,
    next_revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgetInput {
    uri: String,
    expected: SnapshotInput,
}

#[derive(Deserialize)]
struct McpRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpToolCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[allow(clippy::too_many_lines)]
fn dispatch_api<const C: usize, const G: usize, const W: usize>(
    runtime: &mut ContextRuntime<PersistentContextResolver, C, G, W>,
    capability: CapabilityHandle,
    route: &str,
    body: &[u8],
) -> Result<Value, ContextError> {
    match route {
        "/v1/resolve" => {
            let input: UriInput = decode(body)?;
            let target = parse_uri(&input.uri)?;
            let result = runtime.resolve(&ContextRequest::new(
                capability,
                ContextOperation::Resolve,
                target,
            ))?;
            Ok(resolved_value(&result))
        }
        "/v1/list" | "/v1/tree" | "/v1/history" => {
            let input: EnumerationInput = decode(body)?;
            let target = parse_uri(&input.uri)?;
            let operation = match route {
                "/v1/list" => ContextOperation::List,
                "/v1/tree" => ContextOperation::Tree,
                _ => ContextOperation::History,
            };
            let request = ContextRequest::new(capability, operation, target);
            let results = match operation {
                ContextOperation::List => runtime.list(&request, input.limit)?,
                ContextOperation::Tree => runtime.tree(&request, input.limit)?,
                _ => runtime.history(&request, input.limit)?,
            };
            Ok(json!({
                "items": results.iter().map(resolved_value).collect::<Vec<_>>()
            }))
        }
        "/v1/read" => {
            let input: UriInput = decode(body)?;
            let target = parse_uri(&input.uri)?;
            let (resolved, payload) = runtime.read(&ContextRequest::new(
                capability,
                ContextOperation::Read,
                target,
            ))?;
            Ok(json!({
                "resolved": resolved_value(&resolved),
                "payload_base64": BASE64.encode(payload)
            }))
        }
        "/v1/search" => {
            let input: SearchInput = decode(body)?;
            let target = parse_uri(&input.uri)?;
            let hits = runtime.search(
                &ContextRequest::new(capability, ContextOperation::Search, target),
                input.query.as_bytes(),
                input.limit,
            )?;
            Ok(json!({
                "hits": hits.iter().map(|hit| json!({
                    "uri": hit.pinned_uri().to_string(),
                    "revision": hit.revision().to_string(),
                    "score": hit.score(),
                    "alias_generation": hit.alias_generation().map(rvm_context::AliasGeneration::get)
                })).collect::<Vec<_>>()
            }))
        }
        "/v1/verify" => {
            let input: UriInput = decode(body)?;
            let target = parse_uri(&input.uri)?;
            let result = runtime.verify(&ContextRequest::new(
                capability,
                ContextOperation::Verify,
                target,
            ))?;
            Ok(resolved_value(&result))
        }
        "/v1/put" => {
            let input: PutInput = decode(body)?;
            let target = parse_uri(&input.uri)?;
            let rvf = BASE64
                .decode(input.rvf_base64.as_bytes())
                .map_err(|_| ContextError::RvfVerificationFailed)?;
            let result = runtime.put(
                &ContextRequest::new(capability, ContextOperation::Put, target),
                &rvf,
            )?;
            Ok(resolved_value(&result))
        }
        "/v1/cas" => {
            let input: CasInput = decode(body)?;
            let target = parse_uri(&input.uri)?;
            let expected = input.expected.as_ref().map(parse_snapshot).transpose()?;
            let revision = parse_revision(&input.next_revision)?;
            let result = runtime.compare_and_swap_alias(
                &ContextRequest::new(capability, ContextOperation::CompareAndSwapAlias, target),
                expected.as_ref(),
                revision,
            )?;
            Ok(snapshot_value(&result))
        }
        "/v1/forget" => {
            let input: ForgetInput = decode(body)?;
            let target = parse_uri(&input.uri)?;
            let expected = parse_snapshot(&input.expected)?;
            let result = runtime.forget(
                &ContextRequest::new(capability, ContextOperation::Forget, target),
                &expected,
            )?;
            Ok(snapshot_value(&result))
        }
        _ => Err(ContextError::InvalidTarget),
    }
}

fn decode<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, ContextError> {
    serde_json::from_slice(body).map_err(|_| ContextError::InvalidTarget)
}

fn parse_uri(value: &str) -> Result<RuvUri, ContextError> {
    RuvUri::parse(value).map_err(|_| ContextError::InvalidTarget)
}

fn parse_revision(value: &str) -> Result<Revision, ContextError> {
    value.parse().map_err(|_| ContextError::InvalidTarget)
}

fn parse_snapshot(input: &SnapshotInput) -> Result<AliasSnapshot, ContextError> {
    let alias = parse_uri(&input.alias)?;
    let revision = parse_revision(&input.revision)?;
    let generation =
        rvm_context::AliasGeneration::new(input.generation).ok_or(ContextError::InvalidTarget)?;
    AliasSnapshot::new(alias, revision, generation, input.tombstone)
}

fn resolved_value(result: &ResolvedContext) -> Value {
    json!({
        "uri": result.pinned_uri().to_string(),
        "revision": result.revision().to_string(),
        "rvf_len": result.rvf_len(),
        "alias": result.alias().map(snapshot_value)
    })
}

fn snapshot_value(snapshot: &AliasSnapshot) -> Value {
    json!({
        "alias": snapshot.alias().to_string(),
        "revision": snapshot.revision().to_string(),
        "generation": snapshot.generation().get(),
        "tombstone": snapshot.is_tombstone()
    })
}

fn context_error_response(error: ContextError) -> GatewayResponse {
    match error {
        ContextError::AccessDenied
        | ContextError::AliasNotFound
        | ContextError::RevisionNotFound
        | ContextError::Tombstoned => error_response(404, "not_found", "context unavailable"),
        ContextError::AliasConflict | ContextError::RevisionConflict => {
            error_response(409, "conflict", "context mutation conflict")
        }
        ContextError::BackendUnavailable => {
            error_response(503, "unavailable", "context backend unavailable")
        }
        _ => error_response(400, "invalid_request", "context request refused"),
    }
}

fn json_response(status: u16, value: &Value) -> GatewayResponse {
    let body = serde_json::to_vec(value)
        .unwrap_or_else(|_| b"{\"error\":{\"code\":\"internal\"}}".to_vec());
    GatewayResponse { status, body }
}

fn error_response(status: u16, code: &str, message: &str) -> GatewayResponse {
    json_response(
        status,
        &json!({"error": {"code": code, "message": message}}),
    )
}

fn mcp_error(id: &Value, code: i32, message: &str) -> GatewayResponse {
    json_response(
        200,
        &json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    )
}

fn tool_route(name: &str) -> Option<&'static str> {
    match name {
        "ruv_resolve" => Some("/v1/resolve"),
        "ruv_list" => Some("/v1/list"),
        "ruv_tree" => Some("/v1/tree"),
        "ruv_read" => Some("/v1/read"),
        "ruv_search" => Some("/v1/search"),
        "ruv_history" => Some("/v1/history"),
        "ruv_verify" => Some("/v1/verify"),
        "ruv_put" => Some("/v1/put"),
        "ruv_cas" => Some("/v1/cas"),
        "ruv_forget" => Some("/v1/forget"),
        _ => None,
    }
}

fn mcp_tools() -> Value {
    let uri = json!({"type": "string", "description": "Canonical ruv:// URI"});
    json!([
        tool(
            "ruv_resolve",
            "Resolve context metadata",
            &json!({"uri": uri.clone()}),
            &["uri"]
        ),
        tool(
            "ruv_list",
            "List direct child aliases",
            &json!({"uri": uri.clone(), "limit": limit_schema()}),
            &["uri", "limit"]
        ),
        tool(
            "ruv_tree",
            "List descendant aliases",
            &json!({"uri": uri.clone(), "limit": limit_schema()}),
            &["uri", "limit"]
        ),
        tool(
            "ruv_read",
            "Read one verified progressive view",
            &json!({"uri": uri.clone()}),
            &["uri"]
        ),
        tool(
            "ruv_search",
            "Search an authorized context scope",
            &json!({"uri": uri.clone(), "query": {"type": "string", "maxLength": 4096}, "limit": limit_schema()}),
            &["uri", "query", "limit"]
        ),
        tool(
            "ruv_history",
            "List immutable alias revisions",
            &json!({"uri": uri.clone(), "limit": limit_schema()}),
            &["uri", "limit"]
        ),
        tool(
            "ruv_verify",
            "Verify a pinned context RVF",
            &json!({"uri": uri.clone()}),
            &["uri"]
        ),
        tool(
            "ruv_put",
            "Register a pinned base64 RVF",
            &json!({"uri": uri.clone(), "rvf_base64": {"type": "string"}}),
            &["uri", "rvf_base64"]
        ),
        tool(
            "ruv_cas",
            "Compare-and-swap a versionless alias",
            &json!({"uri": uri.clone(), "expected": {"type": ["object", "null"]}, "next_revision": {"type": "string"}}),
            &["uri", "next_revision"]
        ),
        tool(
            "ruv_forget",
            "Cryptographically erase one logical alias",
            &json!({"uri": uri, "expected": {"type": "object"}}),
            &["uri", "expected"]
        )
    ])
}

fn tool(name: &str, description: &str, properties: &Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": properties,
            "required": required
        }
    })
}

fn limit_schema() -> Value {
    json!({"type": "integer", "minimum": 1, "maximum": 64})
}
