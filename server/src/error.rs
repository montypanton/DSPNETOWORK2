// server/src/error.rs
use actix_web::{HttpResponse, ResponseError};
use derive_more::{Display, Error};
use sqlx::Error as SqlxError;

#[derive(Debug, Display, Error)]
pub enum ServerError {
    #[display(fmt = "Database error: {}", _0)]
    DatabaseError(SqlxError),
    
    #[display(fmt = "Authentication error")]
    AuthenticationError,
    
    #[display(fmt = "Not found: {}", resource)]
    NotFoundError { resource: String },
    
    #[display(fmt = "Bad request: {}", message)]
    BadRequestError { message: String },
    
    #[display(fmt = "Internal server error: {}", message)]
    InternalError { message: String },

    #[display(fmt = "Forbidden: {}", message)]
    ForbiddenError { message: String },
}

impl ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServerError::DatabaseError(_) => {
                HttpResponse::InternalServerError().json("Database error occurred")
            }
            ServerError::AuthenticationError => {
                HttpResponse::Unauthorized().json("Authentication failed")
            }
            ServerError::NotFoundError { resource } => {
                HttpResponse::NotFound().json(format!("Resource not found: {}", resource))
            }
            ServerError::BadRequestError { message } => {
                HttpResponse::BadRequest().json(message)
            }
            ServerError::InternalError { message } => {
                HttpResponse::InternalServerError().json(message)
            }
            ServerError::ForbiddenError { message } => {
                HttpResponse::Forbidden().json(message)
            }
        }
    }
}

impl From<SqlxError> for ServerError {
    fn from(error: SqlxError) -> Self {
        ServerError::DatabaseError(error)
    }
}