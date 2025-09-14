use crate::{jwt, AppState};
use actix_web::cookie::time::Duration;
use actix_web::{
    cookie::{Cookie, SameSite},
    delete, get,
    http::header::LOCATION,
    post, web, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::prelude::*;
use image::Luma;
use oauth2::reqwest::async_http_client;
use oauth2::{AuthorizationCode, CsrfToken, Scope, TokenResponse};
use qrcode::QrCode;
use rand::prelude::*;
use rand::{random, rng};
use std::env;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use wayclip_core::log;
use wayclip_core::models::{
    CredentialProvider, DiscordUser, GitHubUser, GoogleUser, User, UserProfile,
};

#[derive(serde::Deserialize)]
pub struct AuthLoginQuery {
    client: Option<String>,
    redirect_uri: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[derive(serde::Deserialize)]
pub struct PasswordRegisterPayload {
    email: String,
    username: String,
    password: String,
}

#[derive(serde::Deserialize)]
pub struct PasswordLoginPayload {
    email: String,
    password: String,
}

#[derive(serde::Deserialize)]
pub struct ResendVerificationPayload {
    email: String,
}

#[derive(serde::Deserialize)]
pub struct TwoFactorVerifyPayload {
    secret: String,
    code: String,
}

#[derive(serde::Deserialize)]
pub struct TwoFactorAuthPayload {
    #[serde(rename = "2fa_token")]
    two_fa_token: String,
    code: String,
}

#[derive(serde::Deserialize)]
pub struct ProviderPath {
    provider: String,
}

async fn upsert_oauth_user(
    db: &sqlx::PgPool,
    provider: &str,
    provider_id: &str,
    email: &str,
    username: &str,
    avatar_url: Option<&str>,
) -> Result<User, sqlx::Error> {
    let mut tx = db.begin().await?;
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(&mut *tx)
        .await?;

    let user = match user {
        Some(mut existing_user) => {
            log!([AUTH] => "User with email '{}' found. Linking {} account.", email, provider);

            if existing_user.deleted_at.is_some() {
                return Err(sqlx::Error::RowNotFound);
            }
            if existing_user.avatar_url.is_none() {
                existing_user.avatar_url = avatar_url.map(String::from);
                sqlx::query("UPDATE users SET avatar_url = $1 WHERE id = $2")
                    .bind(avatar_url)
                    .bind(existing_user.id)
                    .execute(&mut *tx)
                    .await?;
            }
            existing_user
        }
        None => {
            log!([AUTH] => "No user found for email '{}'. Creating new user for {}.", email, provider);
            sqlx::query_as::<_, User>(
                "INSERT INTO users (username, email, avatar_url, email_verified_at) VALUES ($1, $2, $3, NOW()) RETURNING *",
            )
            .bind(username)
            .bind(email)
            .bind(avatar_url)
            .fetch_one(&mut *tx)
            .await?
        }
    };

    sqlx::query("INSERT INTO user_credentials (user_id, provider, provider_id) VALUES ($1, $2::credential_provider, $3) ON CONFLICT (user_id, provider) DO UPDATE SET provider_id = $3").bind(user.id).bind(provider).bind(provider_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(user)
}

fn finalize_auth(user: User, client_type: &str, final_redirect_str: &str) -> HttpResponse {
    let cookie_domain = ".wayclip.com";
    log!([DEBUG] => "Creating JWT for user {}", user.id);
    let jwt = match jwt::create_jwt(user.id, false) {
        Ok(token) => token,
        Err(e) => {
            log!([AUTH] => "ERROR: Failed to create JWT: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to create token");
        }
    };
    if client_type == "cli" {
        let deep_link = format!("{final_redirect_str}?token={jwt}");
        HttpResponse::Found()
            .append_header((LOCATION, deep_link))
            .finish()
    } else {
        HttpResponse::Found()
            .append_header((LOCATION, final_redirect_str))
            .cookie(
                Cookie::build("token", jwt)
                    .path("/")
                    .domain(cookie_domain)
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::None)
                    .finish(),
            )
            .finish()
    }
}

#[get("/github")]
async fn github_login(
    query: web::Query<AuthLoginQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    let client_type = query.client.as_deref().unwrap_or("web");
    let final_redirect_str = query
        .redirect_uri
        .clone()
        .unwrap_or_else(|| "http://localhost:1420".to_string());
    let state = format!(
        "{}:{}:{}",
        CsrfToken::new_random().secret(),
        client_type,
        final_redirect_str
    );
    let (url, _) = data
        .github_oauth_client
        .authorize_url(|| CsrfToken::new(state))
        .add_scope(Scope::new(String::from("read:user")))
        .add_scope(Scope::new(String::from("user:email")))
        .url();
    HttpResponse::Found()
        .append_header((LOCATION, url.to_string()))
        .finish()
}

#[get("/github/callback")]
async fn github_callback(
    query: web::Query<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().body("Invalid state");
    }
    let (client_type, redirect) = (state_parts[1], state_parts[2]);

    let token = match data
        .github_oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
    {
        Ok(t) => t.access_token().secret().to_string(),
        Err(e) => {
            log!([DEBUG] => "GitHub token exchange failed: {:?}", e);
            return HttpResponse::InternalServerError().body("Token exchange failed");
        }
    };
    let client = reqwest::Client::new();
    let user_res: Result<GitHubUser, _> = client
        .get("https://api.github.com/user")
        .bearer_auth(&token)
        .header("User-Agent", "wayclip-api")
        .send()
        .await
        .unwrap()
        .json()
        .await;
    let emails_res: Result<Vec<serde_json::Value>, _> = client
        .get("https://api.github.com/user/emails")
        .bearer_auth(&token)
        .header("User-Agent", "wayclip-api")
        .send()
        .await
        .unwrap()
        .json()
        .await;
    let (gh_user, emails) = match (user_res, emails_res) {
        (Ok(u), Ok(e)) => (u, e),
        _ => return HttpResponse::InternalServerError().body("Failed to fetch GitHub profile"),
    };
    let email = emails
        .into_iter()
        .find(|e| e["primary"] == true && e["verified"] == true)
        .and_then(|e| e["email"].as_str().map(String::from))
        .unwrap_or_else(|| format!("{}@users.noreply.github.com", gh_user.id));
    let user = match upsert_oauth_user(
        &data.db_pool,
        "github",
        &gh_user.id.to_string(),
        &email,
        &gh_user.login,
        gh_user.avatar_url.as_deref(),
    )
    .await
    {
        Ok(u) => {
            if u.is_banned {
                return HttpResponse::Forbidden().body("Your account has been banned.");
            }
            u
        }
        Err(e) => {
            log!([DEBUG] => "GitHub upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return HttpResponse::Forbidden().body(message);
            }
            return HttpResponse::InternalServerError().body("Database error");
        }
    };
    finalize_auth(user, client_type, redirect)
}

#[get("/google")]
async fn google_login(
    query: web::Query<AuthLoginQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    let client_type = query.client.as_deref().unwrap_or("web");
    let final_redirect_str = query
        .redirect_uri
        .clone()
        .unwrap_or_else(|| "http://localhost:1420".to_string());
    let state = format!(
        "{}:{}:{}",
        CsrfToken::new_random().secret(),
        client_type,
        final_redirect_str
    );
    let (url, _) = data
        .google_oauth_client
        .authorize_url(|| CsrfToken::new(state))
        .add_scope(Scope::new(String::from("openid")))
        .add_scope(Scope::new(String::from("profile")))
        .add_scope(Scope::new(String::from("email")))
        .url();
    HttpResponse::Found()
        .append_header((LOCATION, url.to_string()))
        .finish()
}

#[get("/google/callback")]
async fn google_callback(
    query: web::Query<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().body("Invalid state");
    }
    let (client_type, redirect) = (state_parts[1], state_parts[2]);
    let token = match data
        .google_oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
    {
        Ok(t) => t.access_token().secret().to_string(),
        Err(e) => {
            log!([DEBUG] => "Google token exchange failed: {:?}", e);
            return HttpResponse::InternalServerError().body("Token exchange failed");
        }
    };
    let google_user: GoogleUser = match reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
    {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to fetch Google profile")
        }
    };
    let user = match upsert_oauth_user(
        &data.db_pool,
        "google",
        &google_user.sub,
        &google_user.email,
        &google_user.name,
        google_user.picture.as_deref(),
    )
    .await
    {
        Ok(u) => {
            if u.is_banned {
                return HttpResponse::Forbidden().body("Your account has been banned.");
            }
            u
        }
        Err(e) => {
            log!([DEBUG] => "Google upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return HttpResponse::Forbidden().body(message);
            }
            return HttpResponse::InternalServerError().body("Database error");
        }
    };
    finalize_auth(user, client_type, redirect)
}

#[get("/discord")]
async fn discord_login(
    query: web::Query<AuthLoginQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    let client_type = query.client.as_deref().unwrap_or("web");
    let final_redirect_str = query
        .redirect_uri
        .clone()
        .unwrap_or_else(|| "http://localhost:1420".to_string());
    let state = format!(
        "{}:{}:{}",
        CsrfToken::new_random().secret(),
        client_type,
        final_redirect_str
    );
    let (url, _) = data
        .discord_oauth_client
        .authorize_url(|| CsrfToken::new(state))
        .add_scope(Scope::new(String::from("identify")))
        .add_scope(Scope::new(String::from("email")))
        .url();
    HttpResponse::Found()
        .append_header((LOCATION, url.to_string()))
        .finish()
}

#[get("/discord/callback")]
async fn discord_callback(
    query: web::Query<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().body("Invalid state");
    }
    let (client_type, redirect) = (state_parts[1], state_parts[2]);
    let token = match data
        .discord_oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
    {
        Ok(t) => t.access_token().secret().to_string(),
        Err(e) => {
            log!([DEBUG] => "Discord token exchange failed: {:?}", e);
            return HttpResponse::InternalServerError().body("Token exchange failed");
        }
    };
    let discord_user: DiscordUser = match reqwest::Client::new()
        .get("https://discord.com/api/users/@me")
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
    {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to fetch Discord profile")
        }
    };
    let avatar = discord_user.avatar.map(|hash| {
        format!(
            "https://cdn.discordapp.com/avatars/{}/{}",
            discord_user.id, hash
        )
    });
    let email = match discord_user.email {
        Some(e) => e,
        None => {
            return HttpResponse::BadRequest()
                .body("A verified email is required to sign up with Discord.")
        }
    };
    let user = match upsert_oauth_user(
        &data.db_pool,
        "discord",
        &discord_user.id,
        &email,
        &discord_user.username,
        avatar.as_deref(),
    )
    .await
    {
        Ok(u) => {
            if u.is_banned {
                return HttpResponse::Forbidden().body("Your account has been banned.");
            }
            u
        }
        Err(e) => {
            log!([DEBUG] => "Discord upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return HttpResponse::Forbidden().body(message);
            }
            return HttpResponse::InternalServerError().body("Database error");
        }
    };
    finalize_auth(user, client_type, redirect)
}

#[post("/register")]
async fn register_with_password(
    payload: web::Json<PasswordRegisterPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let mut tx = data.db_pool.begin().await.unwrap();
    let new_user: User = match sqlx::query_as::<_, User>(
        "INSERT INTO users (username, email) VALUES ($1, $2) RETURNING *",
    )
    .bind(&payload.username)
    .bind(&payload.email)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(user) => user,
        Err(_) => return HttpResponse::Conflict().body("User with this email already exists."),
    };
    sqlx::query(
        "INSERT INTO user_credentials (user_id, provider, password_hash) VALUES ($1, 'email', $2)",
    )
    .bind(new_user.id)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await
    .unwrap();
    let verification_token = Uuid::new_v4();
    sqlx::query("INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')").bind(verification_token).bind(new_user.id).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();

    if let Err(e) = data.mailer.send_verification_email(
        new_user.email.as_ref().unwrap(),
        &new_user.username,
        &verification_token,
    ) {
        log!([DEBUG] => "Failed to send verification email: {:?}", e);
        return HttpResponse::InternalServerError().body("Could not send verification email.");
    }

    HttpResponse::Ok().json(serde_json::json!({ "message": "Registration successful. Please check your email to verify your account." }))
}

#[get("/verify-email/{token}")]
async fn verify_email(token: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let mut tx = data.db_pool.begin().await.unwrap();
    let record = match sqlx::query!(
        "SELECT user_id FROM email_verification_tokens WHERE token = $1 AND expires_at > NOW()",
        *token
    )
    .fetch_optional(&mut *tx)
    .await
    .unwrap()
    {
        Some(r) => r,
        None => return HttpResponse::BadRequest().body("Invalid or expired verification token."),
    };
    sqlx::query!(
        "UPDATE users SET email_verified_at = NOW() WHERE id = $1",
        record.user_id
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query!(
        "DELETE FROM email_verification_tokens WHERE user_id = $1",
        record.user_id
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let frontend_url =
        env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    HttpResponse::Found()
        .append_header((LOCATION, format!("{}/login?verified=true", frontend_url)))
        .finish()
}

#[post("/resend-verification")]
async fn resend_verification_email(
    payload: web::Json<ResendVerificationPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1").bind(&payload.email).fetch_optional(&data.db_pool).await.unwrap() {
        Some(u) => u,
        None => return HttpResponse::Ok().json(serde_json::json!({ "message": "If an account with that email exists, a new verification link has been sent." })),
    };
    if user.email_verified_at.is_some() {
        return HttpResponse::Ok()
            .json(serde_json::json!({ "message": "Your email is already verified." }));
    }

    let mut tx = data.db_pool.begin().await.unwrap();
    sqlx::query!(
        "DELETE FROM email_verification_tokens WHERE user_id = $1",
        user.id
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let token = Uuid::new_v4();
    sqlx::query("INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')").bind(token).bind(user.id).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();

    data.mailer
        .send_verification_email(user.email.as_ref().unwrap(), &user.username, &token)
        .ok();
    HttpResponse::Ok().json(serde_json::json!({ "message": "If an account with that email exists, a new verification link has been sent." }))
}

#[derive(sqlx::FromRow)]
struct Creds {
    id: Uuid,
    two_factor_enabled: bool,
    email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    is_banned: bool,
}

#[post("/login")]
async fn login_with_password(
    payload: web::Json<PasswordLoginPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let creds = match sqlx::query_as::<_, Creds>(
        r#"SELECT id, two_factor_enabled, email_verified_at, deleted_at, is_banned FROM users WHERE email = $1"#,
    )
    .bind(&payload.email)
    .fetch_optional(&data.db_pool)
    .await
    .unwrap_or(None)
    {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().body("Invalid credentials."),
    };
    if creds.deleted_at.is_some() {
        let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
        return HttpResponse::Forbidden().body(message);
    }
    if creds.is_banned {
        return HttpResponse::Forbidden().body("Your account has been banned.");
    }
    if creds.email_verified_at.is_none() {
        return HttpResponse::Forbidden()
            .body("Please verify your email address before logging in.");
    }
    let hash = sqlx::query_scalar::<_, String>(
        "SELECT password_hash FROM user_credentials WHERE user_id = $1 AND provider = 'email'",
    )
    .bind(creds.id)
    .fetch_one(&data.db_pool)
    .await
    .unwrap();
    if Argon2::default()
        .verify_password(
            payload.password.as_bytes(),
            &PasswordHash::new(&hash).unwrap(),
        )
        .is_err()
    {
        return HttpResponse::Unauthorized().body("Invalid credentials.");
    }

    if creds.two_factor_enabled {
        let temp_jwt = jwt::create_jwt(creds.id, true).unwrap();
        HttpResponse::Ok().json(serde_json::json!({ "2fa_required": true, "2fa_token": temp_jwt }))
    } else {
        let jwt = jwt::create_jwt(creds.id, false).unwrap();
        HttpResponse::Ok()
            .cookie(
                Cookie::build("token", jwt)
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::None)
                    .finish(),
            )
            .json(serde_json::json!({ "success": true, "message": "Login successful" }))
    }
}

#[post("/2fa/setup")]
async fn two_factor_setup(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let user_id = req.extensions().get::<Uuid>().cloned().unwrap();
    let user_email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&data.db_pool)
        .await
        .unwrap_or_default();

    let secret_bytes: Vec<u8> = (0..20).map(|_| random::<u8>()).collect();
    let secret = Secret::Raw(secret_bytes);
    let base32_secret = secret.to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some("Wayclip".to_string()),
        user_email,
    )
    .unwrap();

    let qr_code_url = totp.get_url();
    let qr_code_base64 = match generate_qr_code_base64(&qr_code_url) {
        Ok(base64) => base64,
        Err(e) => {
            log!([DEBUG] => "Failed to generate QR code: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to generate QR code");
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "secret": base32_secret,
        "qr_code_base64": format!("data:image/png;base64,{}", qr_code_base64)
    }))
}

fn generate_qr_code_base64(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let code = QrCode::new(url)?;
    let image = code.render::<Luma<u8>>().build();

    let mut png_bytes = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut png_bytes);
    image.write_to(&mut cursor, image::ImageFormat::Png)?;

    Ok(BASE64_STANDARD.encode(&png_bytes))
}

#[post("/2fa/verify")]
async fn two_factor_verify(
    req: HttpRequest,
    payload: web::Json<TwoFactorVerifyPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user_id = req.extensions().get::<Uuid>().cloned().unwrap();
    let secret = Secret::Encoded(payload.secret.clone());

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        None,
        "".to_string(),
    )
    .unwrap();
    if !totp.check_current(&payload.code).unwrap_or(false) {
        return HttpResponse::BadRequest()
            .body("Invalid code. Please check your authenticator app and try again.");
    }

    sqlx::query("UPDATE users SET two_factor_enabled = TRUE, two_factor_secret = $1 WHERE id = $2")
        .bind(payload.secret.clone())
        .bind(user_id)
        .execute(&data.db_pool)
        .await
        .unwrap();

    let mut recovery_codes = Vec::new();
    let mut tx = data.db_pool.begin().await.unwrap();
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .unwrap();

    for _ in 0..10 {
        let code: String = (0..10)
            .map(|_| "0123456789".chars().choose(&mut rng()).unwrap())
            .collect();
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(code.as_bytes(), &salt)
            .unwrap()
            .to_string();
        sqlx::query("INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user_id)
            .bind(&hash)
            .execute(&mut *tx)
            .await
            .unwrap();
        recovery_codes.push(code);
    }
    tx.commit().await.unwrap();

    HttpResponse::Ok().json(serde_json::json!({ "message": "2FA enabled successfully.", "recovery_codes": recovery_codes }))
}

#[post("/2fa/authenticate")]
async fn two_factor_authenticate(
    payload: web::Json<TwoFactorAuthPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let claims = match jwt::validate_jwt(&payload.two_fa_token) {
        Ok(c) if c.is_2fa => c,
        _ => return HttpResponse::Unauthorized().body("Invalid or expired 2FA token."),
    };

    let secret =
        match sqlx::query_scalar::<_, String>("SELECT two_factor_secret FROM users WHERE id = $1")
            .bind(claims.sub)
            .fetch_one(&data.db_pool)
            .await
            .ok()
        {
            Some(s) => s,
            None => return HttpResponse::NotFound().body("User not found."),
        };

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret).to_bytes().unwrap(),
        None,
        "".to_string(),
    )
    .unwrap();

    if !totp.check_current(&payload.code).unwrap_or(false) {
        return HttpResponse::Unauthorized().body("Invalid 2FA code.");
    }

    let jwt = jwt::create_jwt(claims.sub, false).unwrap();

    HttpResponse::Ok()
        .cookie(
            Cookie::build("token", jwt)
                .path("/")
                .domain(".wayclip.com")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::None)
                .finish(),
        )
        .json(serde_json::json!({ "success": true, "message": "2FA validation successful" }))
}

#[get("/me")]
pub async fn get_me(req: HttpRequest) -> impl Responder {
    let extensions = req.extensions();
    let user_id = match extensions.get::<Uuid>() {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().finish(),
    };
    let data: &web::Data<AppState> = req.app_data().unwrap();
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&data.db_pool)
        .await
    {
        Ok(u) => u,
        Err(_) => return HttpResponse::NotFound().body("User not found"),
    };
    let stats = match sqlx::query!("SELECT COALESCE(SUM(file_size), 0)::BIGINT as total_size, COUNT(*) as clip_count FROM clips WHERE user_id = $1", user_id).fetch_one(&data.db_pool).await {
        Ok(s) => s,
        Err(_) => return HttpResponse::InternalServerError().body("Could not fetch user stats"),
    };
    let connected_accounts = match sqlx::query_as::<_, (CredentialProvider,)>(
        "SELECT provider FROM user_credentials WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&data.db_pool)
    .await
    {
        Ok(providers) => providers.into_iter().map(|(p,)| p).collect(),
        Err(_) => vec![],
    };

    let storage_limit = data.tier_limits.get(&user.tier).cloned().unwrap_or(0);
    let user_profile = UserProfile {
        user,
        storage_used: stats.total_size.unwrap_or(0),
        storage_limit,
        clip_count: stats.clip_count.unwrap_or(0),
        connected_accounts,
    };
    HttpResponse::Ok().json(user_profile)
}

#[delete("/oauth/unlink/{provider}")]
async fn unlink_oauth_provider(
    req: HttpRequest,
    path: web::Path<ProviderPath>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user_id = match req.extensions().get::<Uuid>() {
        Some(id) => *id,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let provider_to_unlink = path.provider.to_lowercase();
    if !["github", "google", "discord", "email"].contains(&provider_to_unlink.as_str()) {
        return HttpResponse::BadRequest().body("Invalid provider specified.");
    }

    let credentials_count: (i64,) =
        match sqlx::query_as("SELECT COUNT(*) FROM user_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&data.db_pool)
            .await
        {
            Ok(count) => count,
            Err(_) => {
                return HttpResponse::InternalServerError().body("Failed to check credentials.")
            }
        };

    if credentials_count.0 <= 1 {
        return HttpResponse::Forbidden()
            .body("You cannot unlink your only authentication method.");
    }

    match sqlx::query(
        "DELETE FROM user_credentials WHERE user_id = $1 AND provider = $2::credential_provider",
    )
    .bind(user_id)
    .bind(provider_to_unlink)
    .execute(&data.db_pool)
    .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                HttpResponse::Ok()
                    .json(serde_json::json!({ "message": "Successfully unlinked provider." }))
            } else {
                HttpResponse::NotFound().body("This provider was not linked to your account.")
            }
        }
        Err(e) => {
            log!([DEBUG] => "Failed to unlink provider: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to unlink provider.")
        }
    }
}

#[delete("/account")]
async fn delete_account(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let user_id = match req.extensions().get::<Uuid>() {
        Some(id) => *id,
        None => return HttpResponse::Unauthorized().finish(),
    };

    match sqlx::query("UPDATE users SET deleted_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(&data.db_pool)
        .await
    {
        Ok(_) => {
            log!([DEBUG] => "User {} marked for deletion.", user_id);
            HttpResponse::Ok().json(serde_json::json!({ "message": "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support." }))
        }
        Err(e) => {
            log!([DEBUG] => "Failed to mark user {} for deletion: {:?}", user_id, e);
            HttpResponse::InternalServerError().body("Failed to schedule account deletion.")
        }
    }
}

#[post("/logout")]
async fn logout() -> impl Responder {
    let cookie = Cookie::build("token", "")
        .path("/")
        .domain(".wayclip.com")
        .expires(actix_web::cookie::time::OffsetDateTime::now_utc() - Duration::days(1))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({ "message": "Logged out successfully." }))
}
