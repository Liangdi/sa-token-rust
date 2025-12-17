// Author: 金书记
//
//! Axum中间件层

use std::task::{Context, Poll};
use tower::{Layer, Service};
use http::{Request, Response};
use sa_token_adapter::context::SaRequest;
use crate::{SaTokenState, adapter::AxumRequestAdapter};
use sa_token_core::{SaTokenContext, router::PathAuthConfig};
use std::sync::Arc;

/// Sa-Token layer for Axum with optional path-based authentication
/// 支持可选路径鉴权的 Axum Sa-Token 层
#[derive(Clone)]
pub struct SaTokenLayer {
    state: SaTokenState,
    /// Optional path authentication configuration
    /// 可选的路径鉴权配置
    path_config: Option<PathAuthConfig>,
}

impl SaTokenLayer {
    pub fn new(state: SaTokenState) -> Self {
        Self { state, path_config: None }
    }
    
    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self { state, path_config: Some(config) }
    }
}

impl<S> Layer<S> for SaTokenLayer {
    type Service = SaTokenMiddleware<S>;
    
    fn layer(&self, inner: S) -> Self::Service {
        SaTokenMiddleware {
            inner,
            state: self.state.clone(),
            path_config: self.path_config.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SaTokenMiddleware<S> {
    pub(crate) inner: S,
    pub(crate) state: SaTokenState,
    /// Optional path authentication configuration
    /// 可选的路径鉴权配置
    pub(crate) path_config: Option<PathAuthConfig>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SaTokenMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    
    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let state = self.state.clone();
        let path_config = self.path_config.clone();
        
        Box::pin(async move {
            if let Some(config) = path_config {
                let path = request.uri().path();
                let token_str = extract_token_from_request(&request, &state);
                let result = sa_token_core::router::process_auth(path, token_str, &config, &state.manager).await;
                
                if result.should_reject() {
                    let mut response = Response::new(ResBody::default());
                    *response.status_mut() = http::StatusCode::UNAUTHORIZED;
                    return Ok(response);
                }
                
                if let Some(token) = &result.token {
                    request.extensions_mut().insert(token.clone());
                }
                if let Some(login_id) = result.login_id() {
                    request.extensions_mut().insert(login_id.to_string());
                }
                
                let ctx = sa_token_core::router::create_context(&result);
                SaTokenContext::set_current(ctx);
                let response = inner.call(request).await;
                SaTokenContext::clear();
                return response;
            }
            
            // No path auth config, use default token extraction and validation
            // 没有路径鉴权配置，使用默认的 token 提取和验证
            let mut ctx = SaTokenContext::new();
            if let Some(token_str) = extract_token_from_request(&request, &state) {
                let token = sa_token_core::token::TokenValue::new(token_str);
                if state.manager.is_valid(&token).await {
                    request.extensions_mut().insert(token.clone());
                    if let Ok(token_info) = state.manager.get_token_info(&token).await {
                        let login_id = token_info.login_id.clone();
                        request.extensions_mut().insert(login_id.clone());
                        ctx.token = Some(token.clone());
                        ctx.token_info = Some(Arc::new(token_info));
                        ctx.login_id = Some(login_id);
                    }
                }
            }
            
            SaTokenContext::set_current(ctx);
            let response = inner.call(request).await;
            SaTokenContext::clear();
            response
        })
    }
}

/// 从请求中提取 Token
/// 
/// 按优先级顺序查找 Token：
/// 1. HTTP Header - `<token_name>: <token>` 或 `<token_name>: Bearer <token>`
/// 2. HTTP Header - `Authorization: <token>` 或 `Authorization: Bearer <token>`（标准头）
/// 3. Cookie - `<token_name>=<token>`
/// 4. Query Parameter - `?<token_name>=<token>`
/// 
/// # 参数
/// - `request` - HTTP 请求
/// - `state` - SaToken 状态（从配置中获取 token_name）
/// 
/// # 返回
/// - `Some(token)` - 找到有效的 token
/// - `None` - 未找到 token
pub fn extract_token_from_request<T>(request: &Request<T>, state: &SaTokenState) -> Option<String> {
    let adapter = AxumRequestAdapter::new(request);
    // 从配置中获取 token_name
    let token_name = &state.manager.config.token_name;
    
    // 1. 优先从 Header 中获取（检查 token_name 配置的头）
    if let Some(token) = adapter.get_header(token_name) {
        return Some(extract_bearer_token(&token));
    }
    
    // 2. 如果 token_name 不是 "Authorization"，也尝试从 "Authorization" 头获取
    if token_name != "Authorization" {
        if let Some(token) = adapter.get_header("Authorization") {
            return Some(extract_bearer_token(&token));
        }
    }
    
    // 3. 从 Cookie 中获取
    if let Some(token) = adapter.get_cookie(token_name) {
        return Some(token);
    }
    
    // 4. 从 Query 参数中获取
    if let Some(query) = request.uri().query() {
        if let Some(token) = parse_query_param(query, token_name) {
            return Some(token);
        }
    }
    
    None
}

/// 提取 Bearer Token
/// 
/// 支持两种格式：
/// - `Bearer <token>` - 标准 Bearer Token 格式
/// - `<token>` - 直接的 Token 字符串
fn extract_bearer_token(header_value: &str) -> String {
    const BEARER_PREFIX: &str = "Bearer ";
    
    if header_value.starts_with(BEARER_PREFIX) {
        // 去除 "Bearer " 前缀
        header_value[BEARER_PREFIX.len()..].trim().to_string()
    } else {
        // 直接返回 token
        header_value.trim().to_string()
    }
}

fn parse_query_param(query: &str, param_name: &str) -> Option<String> {
    for pair in query.split('&') {
        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == param_name {
            return urlencoding::decode(parts[1])
                .ok()
                .map(|s| s.into_owned());
        }
    }
    None
}
