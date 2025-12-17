// Author: 金书记
//
// 中文 | English
// Tide 认证中间件 | Tide authentication middleware

use tide::{Middleware, Request, Response, Next, StatusCode};
use sa_token_core::{StpUtil, error::messages, SaTokenContext, token::TokenValue};
use async_trait::async_trait;
use crate::state::SaTokenState;
use crate::layer::extract_token_from_request;
use std::sync::Arc;
use serde_json::json;

/// 中文 | English
/// 认证中间件 - 验证用户登录状态 | Authentication middleware - verify user login status
///
/// # 示例 | Example
/// ```rust,ignore
/// use tide::prelude::*;
/// use sa_token_plugin_tide::AuthMiddleware;
///
/// let mut app = tide::new();
/// app.with(AuthMiddleware);
/// app.at("/user").get(user_handler);
/// ```
#[derive(Clone)]
pub struct AuthMiddleware;

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for AuthMiddleware {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide::Result {
        // 中文 | English
        // 从请求头中获取 token | Get token from request headers
        let token = req
            .header("Authorization")
            .and_then(|v| v.as_str().strip_prefix("Bearer "))
            .map(|s| s.to_string());
        
        if let Some(token_str) = token {
            // 中文 | English
            // 验证 token 是否有效 | Verify if token is valid
            use sa_token_core::TokenValue;
            let token_value = TokenValue::from(token_str.clone());
            if StpUtil::is_login(&token_value).await {
                // 中文 | English
                // Token 有效，将 login_id 存入扩展数据 | Token valid, store login_id in extensions
                if let Ok(login_id) = StpUtil::get_login_id(&token_value).await {
                    req.set_ext(login_id);
                    return Ok(next.run(req).await);
                }
            }
        }
        
        // 中文 | English
        // Token 无效，返回 401 | Token invalid, return 401
        let mut res = Response::new(StatusCode::Unauthorized);
        res.set_body(r#"{"error":"Unauthorized"}"#);
        res.set_content_type("application/json");
        Ok(res)
    }
}

/// 中文 | English
/// 权限验证中间件 - 验证用户是否拥有指定权限 | Permission middleware - verify if user has specified permissions
///
/// # 示例 | Example
/// ```rust,ignore
/// let mut app = tide::new();
/// app.with(PermissionMiddleware::new("user:read"));
/// ```
#[derive(Clone)]
pub struct PermissionMiddleware {
    permission: String,
}

impl PermissionMiddleware {
    /// 中文 | English
    /// 创建权限验证中间件 | Create permission middleware
    pub fn new(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
        }
    }
}

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for PermissionMiddleware {
    async fn handle(&self, req: Request<State>, next: Next<'_, State>) -> tide::Result {
        // 中文 | English
        // 从扩展数据获取 login_id | Get login_id from extensions
        if let Some(login_id) = req.ext::<String>() {
            // 中文 | English
            // 验证权限 | Verify permission
            if StpUtil::has_permission(login_id, &self.permission).await {
                return Ok(next.run(req).await);
            }
        }
        
        // 中文 | English
        // 无权限，返回 403 | No permission, return 403
        let mut res = Response::new(StatusCode::Forbidden);
        res.set_body(r#"{"error":"Forbidden"}"#);
        res.set_content_type("application/json");
        Ok(res)
    }
}

/// 中文 | English
/// Sa-Token 登录检查中间件 | Sa-Token login check middleware
///
/// 使用标准错误消息，检查当前请求是否已登录 | Uses standard error messages, checks if current request is logged in
#[derive(Clone)]
pub struct SaCheckLoginMiddleware {
    pub state: SaTokenState,
}

impl SaCheckLoginMiddleware {
    /// 中文 | English
    /// 创建新的登录检查中间件 | Create new login check middleware
    pub fn new(state: SaTokenState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SaCheckLoginMiddleware {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide::Result {
        let mut ctx = SaTokenContext::new();
        
        if let Some(token_str) = extract_token_from_request(&req, &self.state.manager.config.token_name) {
            tracing::debug!("Sa-Token(login-check): extracted token from request: {}", token_str);
            let token = TokenValue::new(token_str);
            
            if self.state.manager.is_valid(&token).await {
                if let Ok(token_info) = self.state.manager.get_token_info(&token).await {
                    let login_id = token_info.login_id.clone();
                    req.set_ext(token.clone());
                    req.set_ext(login_id.clone());
                    
                    ctx.token = Some(token.clone());
                    ctx.token_info = Some(Arc::new(token_info));
                    ctx.login_id = Some(login_id);
                    
                    SaTokenContext::set_current(ctx);
                    let result = next.run(req).await;
                    SaTokenContext::clear();
                    return Ok(result);
                }
            }
        }
        
        // 未登录，返回401错误
        let mut res = Response::new(StatusCode::Unauthorized);
        res.set_body(json!({
            "code": 401,
            "message": messages::AUTH_ERROR
        }).to_string());
        res.set_content_type("application/json");
        Ok(res)
    }
}

/// 中文 | English
/// Sa-Token 权限检查中间件 | Sa-Token permission check middleware
///
/// 检查当前请求用户是否拥有指定权限 | Checks if current request user has specified permission
#[derive(Clone)]
pub struct SaCheckPermissionMiddleware {
    pub state: SaTokenState,
    permission: String,
}

impl SaCheckPermissionMiddleware {
    /// 中文 | English
    /// 创建新的权限检查中间件 | Create new permission check middleware
    pub fn new(state: SaTokenState, permission: impl Into<String>) -> Self {
        Self { state, permission: permission.into() }
    }
}

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SaCheckPermissionMiddleware {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide::Result {
        let mut ctx = SaTokenContext::new();
        
        if let Some(token_str) = extract_token_from_request(&req, &self.state.manager.config.token_name) {
            tracing::debug!("Sa-Token(permission-check): extracted token from request: {}", token_str);
            let token = TokenValue::new(token_str);
            
            if self.state.manager.is_valid(&token).await {
                if let Ok(token_info) = self.state.manager.get_token_info(&token).await {
                    let login_id = token_info.login_id.clone();
                    
                    // 检查权限
                    if StpUtil::has_permission(&login_id, &self.permission).await {
                        req.set_ext(token.clone());
                        req.set_ext(login_id.clone());
                        
                        ctx.token = Some(token.clone());
                        ctx.token_info = Some(Arc::new(token_info));
                        ctx.login_id = Some(login_id);
                        
                        SaTokenContext::set_current(ctx);
                        let result = next.run(req).await;
                        SaTokenContext::clear();
                        return Ok(result);
                    }
                }
            }
        }
        
        // 无权限，返回403错误
        let mut res = Response::new(StatusCode::Forbidden);
        res.set_body(json!({
            "code": 403,
            "message": messages::PERMISSION_REQUIRED
        }).to_string());
        res.set_content_type("application/json");
        Ok(res)
    }
}

/// 中文 | English
/// Sa-Token 角色检查中间件 | Sa-Token role check middleware
///
/// 检查当前请求用户是否拥有指定角色 | Checks if current request user has specified role
#[derive(Clone)]
pub struct SaCheckRoleMiddleware {
    pub state: SaTokenState,
    role: String,
}

impl SaCheckRoleMiddleware {
    /// 中文 | English
    /// 创建新的角色检查中间件 | Create new role check middleware
    pub fn new(state: SaTokenState, role: impl Into<String>) -> Self {
        Self { state, role: role.into() }
    }
}

#[async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SaCheckRoleMiddleware {
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide::Result {
        let mut ctx = SaTokenContext::new();
        
        if let Some(token_str) = extract_token_from_request(&req, &self.state.manager.config.token_name) {
            tracing::debug!("Sa-Token(role-check): extracted token from request: {}", token_str);
            let token = TokenValue::new(token_str);
            
            if self.state.manager.is_valid(&token).await {
                if let Ok(token_info) = self.state.manager.get_token_info(&token).await {
                    let login_id = token_info.login_id.clone();
                    
                    // 检查角色
                    if StpUtil::has_role(&login_id, &self.role).await {
                        req.set_ext(token.clone());
                        req.set_ext(login_id.clone());
                        
                        ctx.token = Some(token.clone());
                        ctx.token_info = Some(Arc::new(token_info));
                        ctx.login_id = Some(login_id);
                        
                        SaTokenContext::set_current(ctx);
                        let result = next.run(req).await;
                        SaTokenContext::clear();
                        return Ok(result);
                    }
                }
            }
        }
        
        // 无角色权限，返回403错误
        let mut res = Response::new(StatusCode::Forbidden);
        res.set_body(json!({
            "code": 403,
            "message": messages::ROLE_REQUIRED
        }).to_string());
        res.set_content_type("application/json");
        Ok(res)
    }
}