use crate::{jwt, AppState};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    web, Error, HttpMessage,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use wayclip_core::log;
use wayclip_core::models::UserRole;

pub struct Auth;

impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct AuthMiddleware<S> {
    service: Rc<S>,
}

#[derive(sqlx::FromRow)]
struct UserAuthInfo {
    security_stamp: uuid::Uuid,
    role: UserRole,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            let token = req
                .cookie("token")
                .map(|c| c.value().to_string())
                .or_else(|| {
                    req.headers()
                        .get(header::AUTHORIZATION)
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.strip_prefix("Bearer "))
                        .map(|s| s.to_string())
                });

            if let Some(token_str) = token {
                if let Ok(claims) = jwt::validate_jwt(&token_str) {
                    if claims.is_2fa {
                        log!([AUTH] => "Auth failed: A temporary 2FA token was used for a protected endpoint.");
                    } else if let Some(data) = req.app_data::<web::Data<AppState>>() {
                        let user_info = sqlx::query_as!(
                            UserAuthInfo,
                            r#"
                            SELECT security_stamp, role as "role: UserRole"
                            FROM users
                            WHERE id = $1 AND is_banned = false AND deleted_at IS NULL
                            "#,
                            claims.sub
                        )
                        .fetch_optional(&data.db_pool)
                        .await;

                        match user_info {
                            Ok(Some(info)) if info.security_stamp == claims.sec => {
                                req.extensions_mut().insert(claims.sub);
                                req.extensions_mut().insert(info.role);
                                return service.call(req).await;
                            }
                            Ok(Some(_)) => {
                                log!([AUTH] => "Auth failed for user {}: security stamp mismatch.", claims.sub);
                            }
                            _ => {
                                log!([AUTH] => "Auth failed: User {} not found or is banned/deleted.", claims.sub);
                            }
                        }
                    }
                }
            } else {
                log!([AUTH] => "Auth failed: No token found.");
            }

            Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
        })
    }
}

pub struct AdminAuth;

impl<S, B> Transform<S, ServiceRequest> for AdminAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AdminAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AdminAuthMiddleware { service }))
    }
}

pub struct AdminAuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AdminAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let is_admin = req.extensions().get::<UserRole>() == Some(&UserRole::Admin);

        if is_admin {
            let fut = self.service.call(req);
            Box::pin(fut)
        } else {
            log!([AUTH] => "Forbidden: Non-admin user attempted to access admin route.");
            Box::pin(async move { Err(actix_web::error::ErrorForbidden("Forbidden")) })
        }
    }
}
