use crate::jwt;
use crate::AppState;
use actix_web::web;
use actix_web::{
    body::BoxBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::ok;
use futures_util::future::LocalBoxFuture;
use sqlx::types::Uuid;
use std::future::{ready, Ready};
use std::rc::Rc;
use wayclip_core::log;
use wayclip_core::models::{User, UserRole};

pub struct Auth;

impl<S> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
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

impl<S> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        log!([DEBUG] => "Auth middleware processing request for URI: {}", req.uri());

        let mut token_str: Option<String> = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string());

        if token_str.is_none() {
            if let Some(cookie) = req.cookie("token") {
                log!([DEBUG] => "Found 'token' in httpOnly cookie.");
                token_str = Some(cookie.value().to_string());
            }
        }

        match token_str {
            Some(token) => {
                log!([DEBUG] => "Found token, attempting validation.");
                match jwt::validate_jwt(&token) {
                    Ok(claims) => {
                        let data = req
                            .app_data::<web::Data<AppState>>()
                            .expect("AppState not found")
                            .clone();

                        let svc = self.service.clone();

                        Box::pin(async move {
                            let user_opt =
                                sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
                                    .bind(claims.sub)
                                    .fetch_optional(&data.db_pool)
                                    .await;

                            match user_opt {
                                Ok(Some(user)) if user.deleted_at.is_none() && !user.is_banned => {
                                    req.extensions_mut().insert(claims.sub);
                                    svc.call(req).await.map(|res| res.map_into_boxed_body())
                                }
                                Ok(Some(user)) => {
                                    let reason = if user.deleted_at.is_some() {
                                        "account deleted"
                                    } else {
                                        "banned"
                                    };
                                    log!([AUTH] => "Access denied for user {}: {}", claims.sub, reason);
                                    Ok(req
                                        .into_response(HttpResponse::Unauthorized().finish())
                                        .map_into_boxed_body())
                                }
                                Ok(None) => {
                                    log!([AUTH] => "User not found for ID: {}", claims.sub);
                                    Ok(req
                                        .into_response(HttpResponse::Unauthorized().finish())
                                        .map_into_boxed_body())
                                }
                                Err(e) => {
                                    log!([DEBUG] => "Database error during auth: {:?}", e);
                                    Ok(req
                                        .into_response(HttpResponse::InternalServerError().finish())
                                        .map_into_boxed_body())
                                }
                            }
                        })
                    }
                    Err(e) => {
                        log!([AUTH] => "Token validation failed: {:?}", e);
                        Box::pin(async move {
                            Ok(req
                                .into_response(HttpResponse::Unauthorized().finish())
                                .map_into_boxed_body())
                        })
                    }
                }
            }
            None => {
                log!([AUTH] => "No token found in Authorization header or cookie.");
                Box::pin(async move {
                    Ok(req
                        .into_response(HttpResponse::Unauthorized().finish())
                        .map_into_boxed_body())
                })
            }
        }
    }
}

pub struct AdminAuth;

impl<S> Transform<S, ServiceRequest> for AdminAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = AdminAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AdminAuthMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct AdminAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S> Service<ServiceRequest> for AdminAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let user_id_opt = req.extensions().get::<Uuid>().cloned();

        if user_id_opt.is_none() {
            let fut = ok(req
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_boxed_body());
            return Box::pin(fut);
        }

        let user_id = user_id_opt.unwrap();

        let data = req.app_data::<web::Data<AppState>>().unwrap().clone();
        let service = self.service.clone();

        Box::pin(async move {
            let user_role_query =
                sqlx::query_as::<_, (UserRole,)>("SELECT role FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_optional(&data.db_pool)
                    .await;

            match user_role_query {
                Ok(Some((role,))) if role == UserRole::Admin => {
                    service.call(req).await.map(|res| res.map_into_boxed_body())
                }
                _ => Ok(req
                    .into_response(HttpResponse::Forbidden().finish())
                    .map_into_boxed_body()),
            }
        })
    }
}
