use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;
use wayclip_core::log;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: i64,
    pub iat: i64,
}

pub fn create_jwt(user_id: Uuid) -> Result<String, jsonwebtoken::errors::Error> {
    log!([AUTH] => "Creating new JWT for user ID: {}", user_id);
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let now = Utc::now();
    let expiration = now + Duration::days(7);

    let claims = Claims {
        sub: user_id,
        exp: expiration.timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
}

pub fn validate_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    log!([DEBUG] => "Attempting to validate JWT...");
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::default();

    decode::<Claims>(token, &decoding_key, &validation).map(|token_data| token_data.claims)
}
