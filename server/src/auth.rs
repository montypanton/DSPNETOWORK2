use actix_web::{dev::ServiceRequest, Error, http::header};
use actix_web::error::ErrorUnauthorized;
use futures::future::{ready, Ready};
use actix_web::dev::{Service, Transform};
use std::task::{Context, Poll};
use std::rc::Rc;
use std::pin::Pin;
use futures::Future;
use sqlx::PgPool;

use crate::db;

pub struct Authentication {
    pool: Rc<PgPool>,
}

impl Authentication {
    pub fn new(pool: PgPool) -> Self {
        Authentication {
            pool: Rc::new(pool),
        }
    }
}

// Middleware factory implementation
impl<S, B> Transform<S, ServiceRequest> for Authentication
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthenticationMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware {
            service,
            pool: self.pool.clone(),
        }))
    }
}

pub struct AuthenticationMiddleware<S> {
    service: S,
    pool: Rc<PgPool>,
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse<B>, Error = Error> + 'static + Clone,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        // Skip authentication for the announce endpoint
        if req.path() == "/api/announce" || req.path() == "/api/connection/ping" {
            return Box::pin(self.service.call(req));
        }
        
        // Check for connection token in path for specific endpoints
        let path = req.path().to_string();
        if path.starts_with("/api/messages/") && req.method() == actix_web::http::Method::GET {
            // Extract token from path
            let token = path.replace("/api/messages/", "");
            let pool = self.pool.clone();
            let service = self.service.clone();
            
            return Box::pin(async move {
                // Verify token
                match db::verify_connection_token(&pool, &token).await {
                    Ok(_) => service.call(req).await,
                    Err(_) => Err(ErrorUnauthorized("Invalid token")),
                }
            });
        }
        
        // For all other endpoints, check Authorization header
        let auth_header = match req.headers().get("Authorization") {
            Some(header) => header,
            None => return Box::pin(ready(Err(ErrorUnauthorized("Missing Authorization header")))),
        };
        
        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => return Box::pin(ready(Err(ErrorUnauthorized("Invalid Authorization header")))),
        };
        
        if !auth_str.starts_with("Bearer ") {
            return Box::pin(ready(Err(ErrorUnauthorized("Invalid Authorization header format"))));
        }
        
        let token = auth_str.trim_start_matches("Bearer ").trim();
        let pool = self.pool.clone();
        let service = self.service.clone();
        
        Box::pin(async move {
            // Verify token
            match db::verify_connection_token(&pool, token).await {
                Ok(_) => service.call(req).await,
                Err(_) => Err(ErrorUnauthorized("Invalid token")),
            }
        })
    }
}