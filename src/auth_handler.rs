use crate::{jwt, mailer::Mailer, AppState};
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
use serde_json::json;
use sqlx::PgPool;
use std::env;
use totp_rs::{Algorithm, Secret, TOTP};
use url::Url;
use uuid::Uuid;
use wayclip_core::log;
use wayclip_core::models::{CredentialProvider, DiscordUser, GitHubUser, GoogleUser, User};

const MIN_PASSWORD_LENGTH: usize = 8;

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

#[derive(serde::Deserialize)]
pub struct ForgotPasswordPayload {
    email: String,
}

#[derive(serde::Deserialize)]
pub struct ResetPasswordPayload {
    token: Uuid,
    password: String,
}

fn build_auth_cookie(
    name: &str,
    value: &str,
    expires: Option<actix_web::cookie::time::OffsetDateTime>,
) -> Cookie<'static> {
    let frontend_url =
        env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let owned_name = name.to_owned();
    let owned_value = value.to_owned();

    let mut cookie_builder = Cookie::build(owned_name, owned_value)
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::None);

    if !frontend_url.contains("localhost") {
        cookie_builder = cookie_builder.domain(".wayclip.com");
    }

    if let Some(expiry_time) = expires {
        cookie_builder = cookie_builder.expires(expiry_time);
    }

    cookie_builder.finish()
}

async fn is_device_recognized(
    db: &PgPool,
    user_id: Uuid,
    ip_address: &str,
) -> Result<bool, sqlx::Error> {
    let thirty_days_ago = chrono::Utc::now() - chrono::Duration::days(30);
    let recent_login = sqlx::query!(
        "SELECT EXISTS (
            SELECT 1 FROM user_login_history
            WHERE user_id = $1 AND ip_address = $2 AND created_at > $3
        )",
        user_id,
        ip_address,
        thirty_days_ago
    )
    .fetch_one(db)
    .await?;

    Ok(recent_login.exists.unwrap_or(false))
}

async fn record_successful_login(
    db: &PgPool,
    user: &User,
    req: &HttpRequest,
    mailer: &Mailer,
) -> bool {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let mut was_unrecognized = false;

    if user.two_factor_enabled {
        match is_device_recognized(db, user.id, &ip).await {
            Ok(true) => {}
            Ok(false) => {
                was_unrecognized = true;
                if let Some(email) = &user.email {
                    let mailer_clone = mailer.clone();
                    let email_clone = email.clone();
                    let username_clone = user.username.clone();
                    let ip_clone = ip.clone();

                    actix_web::rt::spawn(async move {
                        if let Err(e) = mailer_clone.send_unrecognized_device_email(
                            &email_clone,
                            &username_clone,
                            &ip_clone,
                        ) {
                            log!([DEBUG] => "Failed to send unrecognized device email: {:?}", e);
                        }
                    });
                }
            }
            Err(e) => {
                log!([DEBUG] => "Failed to check device recognition for user {}: {:?}", user.id, e);
            }
        }
    }

    if let Err(e) = sqlx::query!(
        "UPDATE users SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2",
        &ip,
        user.id
    )
    .execute(db)
    .await
    {
        log!([DEBUG] => "Failed to update last_login info for user {}: {:?}", user.id, e);
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO user_login_history (user_id, ip_address) VALUES ($1, $2)",
        user.id,
        &ip
    )
    .execute(db)
    .await
    {
        log!([DEBUG] => "Failed to record login history for user {}: {:?}", user.id, e);
    }

    was_unrecognized
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

fn handle_oauth_error(client_type: &str, message: &str) -> HttpResponse {
    if client_type == "web" {
        let frontend_url =
            env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let mut redirect_url = Url::parse(&format!("{frontend_url}/login")).unwrap();
        redirect_url.query_pairs_mut().append_pair("error", message);
        HttpResponse::Found()
            .append_header((LOCATION, redirect_url.to_string()))
            .finish()
    } else {
        HttpResponse::Forbidden().json(json!({ "message": message }))
    }
}

async fn finalize_login(
    user: User,
    client_type: &str,
    final_redirect_str: &str,
    data: &web::Data<AppState>,
    req: &HttpRequest,
) -> HttpResponse {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let device_recognized = is_device_recognized(&data.db_pool, user.id, &ip)
        .await
        .unwrap_or(true);

    if user.two_factor_enabled && !device_recognized {
        let temp_jwt = match jwt::create_jwt(user.id, &user.security_stamp, true) {
            Ok(token) => token,
            Err(e) => {
                log!([AUTH] => "ERROR: Failed to create 2FA JWT: {:?}", e);
                return HttpResponse::InternalServerError()
                    .json(json!({ "message": "Failed to create 2FA token" }));
            }
        };

        if client_type == "cli" {
            let deep_link = format!("{final_redirect_str}?2fa_token={temp_jwt}");
            return HttpResponse::Found()
                .append_header((LOCATION, deep_link))
                .finish();
        } else {
            let frontend_url =
                env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
            let two_fa_url = format!("{frontend_url}/login?2fa_required=true&token={temp_jwt}");
            return HttpResponse::Found()
                .append_header((LOCATION, two_fa_url))
                .finish();
        }
    }

    record_successful_login(&data.db_pool, &user, req, &data.mailer).await;

    let final_jwt = match jwt::create_jwt(user.id, &user.security_stamp, false) {
        Ok(token) => token,
        Err(e) => {
            log!([AUTH] => "ERROR: Failed to create final JWT: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to create session token" }));
        }
    };

    if client_type == "cli" {
        let deep_link = format!("{final_redirect_str}?token={final_jwt}");
        HttpResponse::Found()
            .append_header((LOCATION, deep_link))
            .finish()
    } else {
        let auth_cookie = build_auth_cookie("token", &final_jwt, None);
        HttpResponse::Found()
            .append_header((LOCATION, final_redirect_str))
            .cookie(auth_cookie)
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
    req: HttpRequest,
    query: web::Query<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid state" }));
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
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Token exchange failed" }));
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
        _ => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to fetch GitHub profile" }))
        }
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
                return handle_oauth_error(client_type, "Your account has been banned.");
            }
            u
        }
        Err(e) => {
            log!([DEBUG] => "GitHub upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return handle_oauth_error(client_type, message);
            }
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error" }));
        }
    };
    finalize_login(user, client_type, redirect, &data, &req).await
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
    req: HttpRequest,
    query: web::Query<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid state" }));
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
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Token exchange failed" }));
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
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to fetch Google profile" }))
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
                return handle_oauth_error(client_type, "Your account has been banned.");
            }
            u
        }
        Err(e) => {
            log!([DEBUG] => "Google upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return handle_oauth_error(client_type, message);
            }
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error" }));
        }
    };
    finalize_login(user, client_type, redirect, &data, &req).await
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
    req: HttpRequest,
    query: web::Query<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid state" }));
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
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Token exchange failed" }));
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
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to fetch Discord profile" }))
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
            return HttpResponse::BadRequest().json(
                json!({ "message": "A verified email is required to sign up with Discord." }),
            )
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
                return handle_oauth_error(client_type, "Your account has been banned.");
            }
            u
        }
        Err(e) => {
            log!([DEBUG] => "Discord upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return handle_oauth_error(client_type, message);
            }
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error" }));
        }
    };
    finalize_login(user, client_type, redirect, &data, &req).await
}

#[post("/register")]
async fn register_with_password(
    payload: web::Json<PasswordRegisterPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    if payload.password.len() < MIN_PASSWORD_LENGTH {
        return HttpResponse::BadRequest().json(json!({ "message": format!("Password must be at least {} characters long.", MIN_PASSWORD_LENGTH) }));
    }
    if !validator::ValidateEmail::validate_email(&payload.email) {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid email format." }));
    }
    if payload.username.len() < 3
        || payload.username.len() > 20
        || !payload.username.chars().all(|c| c.is_alphanumeric())
    {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Username must be 3-20 alphanumeric characters." }));
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            log!([DEBUG] => "Password hashing failed: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Could not process registration." }));
        }
    };

    let mut tx = match data.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error." }))
        }
    };

    let new_user: User = match sqlx::query_as::<_, User>(
        "INSERT INTO users (username, email) VALUES ($1, $2) RETURNING *",
    )
    .bind(&payload.username)
    .bind(&payload.email)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::Conflict()
                .json(json!({ "message": "User with this email already exists." }))
        }
    };

    if sqlx::query(
        "INSERT INTO user_credentials (user_id, provider, password_hash) VALUES ($1, 'email', $2)",
    )
    .bind(new_user.id)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Could not save credentials." }));
    }

    let verification_token = Uuid::new_v4();
    if sqlx::query("INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')").bind(verification_token).bind(new_user.id).execute(&mut *tx).await.is_err() {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(json!({ "message": "Could not create verification token." }));
    }

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Database transaction failed." }));
    }

    if let Err(e) = data.mailer.send_verification_email(
        new_user.email.as_ref().unwrap(),
        &new_user.username,
        &verification_token,
    ) {
        log!([DEBUG] => "Failed to send verification email: {:?}", e);
    }

    HttpResponse::Ok().json(serde_json::json!({ "message": "Registration successful. Please check your email to verify your account." }))
}

#[get("/verify-email/{token}")]
async fn verify_email(token: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let mut tx = match data.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error." }))
        }
    };

    let record = match sqlx::query!(
        "SELECT user_id FROM email_verification_tokens WHERE token = $1 AND expires_at > NOW()",
        *token
    )
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::BadRequest()
                .json(json!({ "message": "Invalid or expired verification token." }))
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error." }))
        }
    };

    if sqlx::query!(
        "UPDATE users SET email_verified_at = NOW() WHERE id = $1",
        record.user_id
    )
    .execute(&mut *tx)
    .await
    .is_err()
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Failed to verify email." }));
    }

    if sqlx::query!(
        "DELETE FROM email_verification_tokens WHERE user_id = $1",
        record.user_id
    )
    .execute(&mut *tx)
    .await
    .is_err()
    {
        log!([DEBUG] => "Failed to delete verification token for user {}", record.user_id);
    }

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Database transaction failed." }));
    }

    let frontend_url =
        env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    HttpResponse::Found()
        .append_header((LOCATION, format!("{frontend_url}/login?verified=true")))
        .finish()
}

#[post("/resend-verification")]
async fn resend_verification_email(
    payload: web::Json<ResendVerificationPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let success_message = serde_json::json!({ "message": "If an account with that email exists, a new verification link has been sent." });

    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(&data.db_pool)
        .await
    {
        Ok(Some(u)) => u,
        _ => return HttpResponse::Ok().json(success_message),
    };

    if user.email_verified_at.is_some() {
        return HttpResponse::Ok()
            .json(serde_json::json!({ "message": "Your email is already verified." }));
    }

    if user.deleted_at.is_some() {
        return HttpResponse::Ok().json(success_message);
    }

    let mut tx = match data.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error." }))
        }
    };

    sqlx::query!(
        "DELETE FROM email_verification_tokens WHERE user_id = $1",
        user.id
    )
    .execute(&mut *tx)
    .await
    .ok();

    let token = Uuid::new_v4();
    if sqlx::query("INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')").bind(token).bind(user.id).execute(&mut *tx).await.is_err() {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(json!({ "message": "Could not generate new token." }));
    }

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Database transaction failed." }));
    }

    data.mailer
        .send_verification_email(user.email.as_ref().unwrap(), &user.username, &token)
        .ok();

    HttpResponse::Ok().json(success_message)
}

#[post("/login")]
async fn login_with_password(
    req: HttpRequest,
    payload: web::Json<PasswordLoginPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user = match sqlx::query_as::<_, User>(r#"SELECT * FROM users WHERE email = $1"#)
        .bind(&payload.email)
        .fetch_optional(&data.db_pool)
        .await
        .unwrap_or(None)
    {
        Some(u) => u,
        None => {
            return HttpResponse::Unauthorized().json(json!({ "message": "Invalid credentials." }))
        }
    };

    if user.deleted_at.is_some() {
        let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
        return HttpResponse::Forbidden().json(json!({ "message": message }));
    }
    if user.is_banned {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Your account has been banned." }));
    }
    if user.email_verified_at.is_none() {
        return HttpResponse::Forbidden().json(json!({ "error_code": "EMAIL_NOT_VERIFIED", "message": "Please verify your email address before logging in." }));
    }

    let hash = match sqlx::query_scalar::<_, String>(
        "SELECT password_hash FROM user_credentials WHERE user_id = $1 AND provider = 'email'",
    )
    .bind(user.id)
    .fetch_optional(&data.db_pool)
    .await
    {
        Ok(Some(h)) => h,
        _ => {
            return HttpResponse::Unauthorized().json(json!({ "message": "Invalid credentials." }))
        }
    };

    let password_hash = match PasswordHash::new(&hash) {
        Ok(ph) => ph,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Error validating credentials." }))
        }
    };

    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &password_hash)
        .is_err()
    {
        return HttpResponse::Unauthorized().json(json!({ "message": "Invalid credentials." }));
    }

    finalize_login(user, "web", "/", &data, &req).await
}

#[post("/forgot-password")]
async fn forgot_password(
    payload: web::Json<ForgotPasswordPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let success_message = serde_json::json!({ "message": "If an account with that email exists, a password reset link has been sent." });

    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(&data.db_pool)
        .await
    {
        Ok(Some(u)) => u,
        _ => return HttpResponse::Ok().json(success_message),
    };

    if user.deleted_at.is_some() {
        return HttpResponse::Ok().json(success_message);
    }

    let mut tx = match data.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error." }))
        }
    };

    let token = Uuid::new_v4();
    if sqlx::query(
        "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(token)
    .bind(user.id)
    .execute(&mut *tx)
    .await.is_err() {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(json!({ "message": "Failed to generate reset token." }));
    }

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Database transaction failed." }));
    }

    if let Err(e) =
        data.mailer
            .send_password_reset_email(user.email.as_ref().unwrap(), &user.username, &token)
    {
        log!([DEBUG] => "Failed to send password reset email: {:?}", e);
    }

    HttpResponse::Ok().json(success_message)
}

#[post("/reset-password")]
async fn reset_password(
    payload: web::Json<ResetPasswordPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    if payload.password.len() < MIN_PASSWORD_LENGTH {
        return HttpResponse::BadRequest().json(json!({ "message": format!("Password must be at least {} characters long.", MIN_PASSWORD_LENGTH) }));
    }

    let mut tx = match data.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error." }))
        }
    };

    let record = match sqlx::query!(
        "SELECT user_id FROM password_reset_tokens WHERE token = $1 AND expires_at > NOW()",
        payload.token
    )
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::BadRequest()
                .json(json!({ "message": "Invalid or expired password reset token." }))
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error." }))
        }
    };

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            log!([DEBUG] => "Password hashing failed during reset: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Could not process password reset." }));
        }
    };

    if sqlx::query!(
        "UPDATE user_credentials SET password_hash = $1 WHERE user_id = $2 AND provider = 'email'",
        password_hash,
        record.user_id
    )
    .execute(&mut *tx)
    .await
    .is_err()
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Failed to update password." }));
    }

    sqlx::query!(
        "DELETE FROM password_reset_tokens WHERE user_id = $1",
        record.user_id
    )
    .execute(&mut *tx)
    .await
    .ok();

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Database transaction failed." }));
    }

    HttpResponse::Ok()
        .json(serde_json::json!({ "message": "Password has been reset successfully." }))
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
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to generate QR code" }));
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
            .json(json!({ "message": "Invalid code. Please check your authenticator app and try again." }));
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
            .map(|_| {
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                    .chars()
                    .choose(&mut rng())
                    .unwrap()
            })
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
    req: HttpRequest,
    payload: web::Json<TwoFactorAuthPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let claims = match jwt::validate_jwt(&payload.two_fa_token) {
        Ok(c) if c.is_2fa => c,
        _ => {
            return HttpResponse::Unauthorized()
                .json(json!({ "message": "Invalid or expired 2FA token." }))
        }
    };

    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(claims.sub)
        .fetch_one(&data.db_pool)
        .await
    {
        Ok(u) => u,
        Err(_) => return HttpResponse::NotFound().json(json!({ "message": "User not found." })),
    };

    if claims.sec != user.security_stamp {
        return HttpResponse::Unauthorized()
            .json(json!({ "message": "Invalid or expired 2FA token." }));
    }

    let user_clone = user.clone();

    let secret = match user_clone.two_factor_secret {
        Some(s) => s,
        None => {
            return HttpResponse::BadRequest()
                .json(json!({ "message": "2FA is not enabled for this user." }))
        }
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

    let mut code_is_valid = totp.check_current(&payload.code).unwrap_or(false);
    let mut used_recovery_code = false;

    if !code_is_valid {
        let recovery_codes = sqlx::query_as::<_, (String,)>(
            "SELECT code_hash FROM user_recovery_codes WHERE user_id = $1",
        )
        .bind(claims.sub)
        .fetch_all(&data.db_pool)
        .await
        .unwrap_or_default();

        for (code_hash,) in recovery_codes {
            if Argon2::default()
                .verify_password(
                    payload.code.as_bytes(),
                    &PasswordHash::new(&code_hash).unwrap(),
                )
                .is_ok()
            {
                sqlx::query(
                    "DELETE FROM user_recovery_codes WHERE user_id = $1 AND code_hash = $2",
                )
                .bind(claims.sub)
                .bind(code_hash)
                .execute(&data.db_pool)
                .await
                .ok();
                code_is_valid = true;
                used_recovery_code = true;
                break;
            }
        }
    }

    if code_is_valid {
        record_successful_login(&data.db_pool, &user, &req, &data.mailer).await;

        let jwt = jwt::create_jwt(user.id, &user.security_stamp, false).unwrap();
        let message = if used_recovery_code {
            "2FA validation successful with recovery code."
        } else {
            "2FA validation successful"
        };
        let auth_cookie = build_auth_cookie("token", &jwt, None);
        return HttpResponse::Ok()
            .cookie(auth_cookie)
            .json(serde_json::json!({ "success": true, "message": message }));
    }

    HttpResponse::Unauthorized().json(json!({ "message": "Invalid 2FA code or recovery code." }))
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
        Err(_) => return HttpResponse::NotFound().json(json!({ "message": "User not found" })),
    };
    let stats = match sqlx::query!("SELECT COALESCE(SUM(file_size), 0)::BIGINT as total_size, COUNT(*) as clip_count FROM clips WHERE user_id = $1", user_id).fetch_one(&data.db_pool).await {
        Ok(s) => s,
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Could not fetch user stats" })),
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

    let profile = json!({
        "id": user.id,
        "github_id": user.github_id,
        "username": user.username,
        "email": user.email,
        "avatar_url": user.avatar_url,
        "tier": user.tier,
        "is_banned": user.is_banned,
        "two_factor_enabled": user.two_factor_enabled,
        "email_verified_at": user.email_verified_at,
        "created_at": user.created_at,
        "role": user.role,
        "last_login_at": user.last_login_at,
        "last_login_ip": user.last_login_ip,
        "storage_used": stats.total_size.unwrap_or(0),
        "storage_limit": storage_limit,
        "clip_count": stats.clip_count.unwrap_or(0),
        "connected_accounts": connected_accounts,
    });

    HttpResponse::Ok().json(profile)
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
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Invalid provider specified." }));
    }

    let credentials_count: (i64,) =
        match sqlx::query_as("SELECT COUNT(*) FROM user_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&data.db_pool)
            .await
        {
            Ok(count) => count,
            Err(_) => {
                return HttpResponse::InternalServerError()
                    .json(json!({ "message": "Failed to check credentials." }))
            }
        };

    if credentials_count.0 <= 1 {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "You cannot unlink your only authentication method." }));
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
                HttpResponse::NotFound()
                    .json(json!({ "message": "This provider was not linked to your account." }))
            }
        }
        Err(e) => {
            log!([DEBUG] => "Failed to unlink provider: {:?}", e);
            HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to unlink provider." }))
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
            HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to schedule account deletion." }))
        }
    }
}

#[post("/logout")]
async fn logout() -> impl Responder {
    let expiry = actix_web::cookie::time::OffsetDateTime::now_utc() - Duration::days(1);
    let cookie = build_auth_cookie("token", "", Some(expiry));
    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({ "message": "Logged out successfully." }))
}

#[post("/logout-devices")]
async fn logout_all_devices(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let user_id = match req.extensions().get::<Uuid>() {
        Some(id) => *id,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let new_stamp = Uuid::new_v4();

    match sqlx::query("UPDATE users SET security_stamp = $1 WHERE id = $2")
        .bind(new_stamp)
        .bind(user_id)
        .execute(&data.db_pool)
        .await
    {
        Ok(_) => {
            log!([DEBUG] => "User {} logged out all other devices.", user_id);
            let new_jwt = jwt::create_jwt(user_id, &new_stamp, false).unwrap();
            let auth_cookie = build_auth_cookie("token", &new_jwt, None);
            HttpResponse::Ok()
                .cookie(auth_cookie)
                .json(serde_json::json!({ "message": "All other sessions have been logged out." }))
        }
        Err(e) => {
            log!([DEBUG] => "Failed to logout devices for user {}: {:?}", user_id, e);
            HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to log out other devices." }))
        }
    }
}
