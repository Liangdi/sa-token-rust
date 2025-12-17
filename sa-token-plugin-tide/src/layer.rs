use tide::{Middleware, Request, Result, Next};
use sa_token_core::{token::TokenValue, SaTokenContext};
use std::sync::Arc;
use crate::state::SaTokenState;
use sa_token_adapter::utils::{parse_cookies, parse_query_string, extract_bearer_token as utils_extract_bearer_token};

use sa_token_core::router::PathAuthConfig;

/// Sa-Token layer for Tide with optional path-based authentication
/// 支持可选路径鉴权的 Tide Sa-Token 层
#[derive(Clone)]
pub struct SaTokenLayer {
    state: SaTokenState,
    /// Optional path authentication configuration
    /// 可选的路径鉴权配置
    path_config: Option<PathAuthConfig>,
}

impl SaTokenLayer {
    /// Create layer without path authentication
    /// 创建不带路径鉴权的层
    pub fn new(state: SaTokenState) -> Self {
        Self { state, path_config: None }
    }
    
    /// Create layer with path-based authentication
    /// 创建带路径鉴权的层
    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self { state, path_config: Some(config) }
    }
}

#[tide::utils::async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SaTokenLayer {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> Result {
        if let Some(config) = &self.path_config {
            let path = req.url().path();
            let token_str = extract_token_from_request(&req, &self.state.manager.config.token_name);
            let result = sa_token_core::router::process_auth(path, token_str, config, &self.state.manager).await;
            
            if result.should_reject() {
                return Ok(tide::Response::builder(tide::StatusCode::Unauthorized).build());
            }
            
            let ctx = sa_token_core::router::create_context(&result);
            SaTokenContext::set_current(ctx);
            let response = next.run(req).await;
            SaTokenContext::clear();
            return Ok(response);
        }
        
        // No path auth config, use default token extraction and validation
        // 没有路径鉴权配置，使用默认的 token 提取和验证
        let mut ctx = SaTokenContext::new();
        if let Some(token_str) = extract_token_from_request(&req, &self.state.manager.config.token_name) {
            tracing::debug!("Sa-Token: extracted token from request: {}", token_str);
            let token = TokenValue::new(token_str);
            
            if self.state.manager.is_valid(&token).await {
                req.set_ext(token.clone());
                
                if let Ok(token_info) = self.state.manager.get_token_info(&token).await {
                    let login_id = token_info.login_id.clone();
                    req.set_ext(login_id.clone());
                    
                    ctx.token = Some(token.clone());
                    ctx.token_info = Some(Arc::new(token_info));
                    ctx.login_id = Some(login_id);
                }
            }
        }
        
        SaTokenContext::set_current(ctx);
        let result = next.run(req).await;
        SaTokenContext::clear();
        Ok(result)
    }
}

/// 中文 | English
/// 从请求中提取 token | Extract token from request
///
/// 按以下顺序尝试提取 token: | Try to extract token in the following order:
/// 1. 从指定名称的请求头 | From specified header name
/// 2. 从 Authorization 请求头 | From Authorization header
/// 3. 从 Cookie | From cookie
/// 4. 从查询参数 | From query parameter
pub fn extract_token_from_request<State>(req: &Request<State>, token_name: &str) -> Option<String> {
    if let Some(header_value) = req.header(token_name) {
        if let Some(value_str) = header_value.get(0) {
            let value_str = value_str.as_str();
            if !value_str.is_empty() {
                if let Some(token) = utils_extract_bearer_token(value_str) {
                    return Some(token);
                }
            }
        }
    }
    
    // 2. 从 Authorization 请求头提取 | Extract from Authorization header
    if let Some(auth_header) = req.header("authorization") {
        if let Some(auth_str) = auth_header.get(0) {
            let auth_str = auth_str.as_str();
            if !auth_str.is_empty() {
                if let Some(token) = utils_extract_bearer_token(auth_str) {
                    return Some(token);
                }
            }
        }
    }
    
    // 3. 从 Cookie 提取 | Extract from cookie
    if let Some(cookie_header) = req.header("cookie") {
        if let Some(cookie_str) = cookie_header.get(0) {
            let cookies = parse_cookies(cookie_str.as_str());
            if let Some(token) = cookies.get(token_name) {
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }
    
    // 4. 从查询参数提取 | Extract from query parameter
    if let Some(query) = req.url().query() {
        let params = parse_query_string(query);
        if let Some(token) = params.get(token_name) {
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    
    None
}
