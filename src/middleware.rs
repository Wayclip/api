use crate::jwt;
use actix_web::{
    body::BoxBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use wayclip_core::log;

pub struct Auth;

impl<S> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware { service }))
    }
}

pub struct AuthMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        log!([DEBUG] => "Auth middleware processing request for URI: {}", req.uri());
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));

        match token {
            Some(token) => {
                log!([DEBUG] => "Found Bearer token in Authorization header.");
                match jwt::validate_jwt(token) {
                    Ok(claims) => {
                        log!([AUTH] => "Token validation successful for user ID: {}", claims.sub);
                        req.extensions_mut().insert(claims.sub);
                        let fut = self.service.call(req);
                        Box::pin(fut)
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
                log!([AUTH] => "No Authorization header or Bearer token found.");
                Box::pin(async move {
                    Ok(req
                        .into_response(HttpResponse::Unauthorized().finish())
                        .map_into_boxed_body())
                })
            }
        }
    }
}
