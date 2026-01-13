use crate::log;
use crate::session;
use crate::settings::Settings;
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
use rand::distr::Alphanumeric;
use rand::seq::IteratorRandom;
use rand::{random, Rng};
use serde_json::json;
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};
use url::Url;
use uuid::Uuid;
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
    let config = Settings::new().expect("Failed to load settings");
    let frontend_url = &config.frontend_url;

    let is_localhost = frontend_url.contains("localhost") || frontend_url.contains("127.0.0.1");

    let mut cookie_builder = Cookie::build(name.to_owned(), value.to_owned())
        .path("/")
        .http_only(true);

    if is_localhost {
        cookie_builder = cookie_builder.secure(false).same_site(SameSite::Lax);
    } else {
        cookie_builder = cookie_builder.secure(true).same_site(SameSite::None);
    }

    if !is_localhost {
        let root_domain = Url::parse(frontend_url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(|host| host.to_string()))
            .and_then(|host| {
                let parts: Vec<&str> = host.split('.').collect();
                if parts.len() >= 2 {
                    Some(format!(".{}", parts[parts.len() - 2..].join(".")))
                } else {
                    None
                }
            });

        if let Some(domain) = root_domain {
            cookie_builder = cookie_builder.domain(domain);
        }
    }

    if let Some(expiry_time) = expires {
        cookie_builder = cookie_builder.expires(expiry_time);
    }

    cookie_builder.finish()
}

async fn record_successful_login(
    db: &PgPool,
    user: &User,
    req: &HttpRequest,
    mailer: Option<&Mailer>,
) -> String {
    let user_agent = session::get_user_agent(req);
    let existing_sessions_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM user_sessions WHERE user_id = $1",
        user.id
    )
    .fetch_one(db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    if existing_sessions_count > 0 {
        if let Some(mailer) = mailer {
            if let Some(email) = &user.email {
                let email_clone = email.clone();
                let username_clone = user.username.clone();
                let parsed_ua = session::parse_user_agent(&user_agent);
                let mailer_clone = mailer.clone();

                actix_web::rt::spawn(async move {
                    if let Err(e) =
                        mailer_clone.send_new_login_email(&email_clone, &username_clone, &parsed_ua)
                    {
                        log!([DEBUG] => "Failed to send new login email: {:?}", e);
                    }
                });
            }
        }
    }

    let session_token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    if let Err(e) = sqlx::query!(
        "INSERT INTO user_sessions (user_id, session_token, user_agent, last_seen_at) VALUES ($1, $2, $3, NOW())",
        user.id,
        &session_token,
        &user_agent
    )
    .execute(db)
    .await
    {
        log!([DEBUG] => "Failed to record new session for user {}: {:?}", user.id, e);
    }

    if let Err(e) = sqlx::query!(
        "UPDATE users SET last_login_at = NOW() WHERE id = $1",
        user.id
    )
    .execute(db)
    .await
    {
        log!([DEBUG] => "Failed to update last_login_at for user {}: {:?}", user.id, e);
    }

    session_token
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

    sqlx::query(
        "INSERT INTO users (username, email, avatar_url, email_verified_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT (email) DO NOTHING",
    )
    .bind(username)
    .bind(email)
    .bind(avatar_url)
    .execute(&mut *tx)
    .await?;

    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET avatar_url = COALESCE(avatar_url, $2) WHERE email = $1 RETURNING *",
    )
    .bind(email)
    .bind(avatar_url)
    .fetch_one(&mut *tx)
    .await?;

    if user.deleted_at.is_some() {
        tx.rollback().await?;
        return Err(sqlx::Error::RowNotFound);
    }

    sqlx::query("INSERT INTO user_credentials (user_id, provider, provider_id) VALUES ($1, $2::credential_provider, $3) ON CONFLICT (user_id, provider) DO UPDATE SET provider_id = $3")
        .bind(user.id)
        .bind(provider)
        .bind(provider_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(user)
}

fn handle_oauth_error(settings: &Settings, client_type: &str, message: &str) -> HttpResponse {
    if client_type == "web" {
        let frontend_url = settings.frontend_url.clone();
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
    is_json_requested: bool,
) -> HttpResponse {
    let settings = data.settings.clone();

    if user.two_factor_enabled {
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
            let frontend_url = settings.frontend_url.clone();
            let two_fa_url = format!("{frontend_url}/login?2fa_required=true&token={temp_jwt}");
            return HttpResponse::Found()
                .append_header((LOCATION, two_fa_url))
                .finish();
        }
    }

    let session_token =
        record_successful_login(&data.db_pool, &user, req, data.mailer.as_ref()).await;

    let token_to_send = match jwt::create_jwt(user.id, &user.security_stamp, false) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let auth_cookie = build_auth_cookie("session_token", &session_token, None);

    if client_type == "cli" {
        let deep_link = format!("{final_redirect_str}?token={token_to_send}");
        HttpResponse::Found()
            .append_header((LOCATION, deep_link))
            .finish()
    } else if is_json_requested {
        HttpResponse::Ok()
            .cookie(auth_cookie)
            .json(json!({ "success": true, "message": "Logged in successfully" }))
    } else {
        HttpResponse::Found()
            .append_header((LOCATION, final_redirect_str.to_string()))
            .cookie(auth_cookie)
            .finish()
    }
}

#[get("/github")]
async fn github_login(
    query: web::Query<AuthLoginQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
    if settings.github_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let gh_client = data
        .github_oauth_client
        .clone()
        .expect("Missing GitHub OAuth client");
    let client_type = query.client.as_deref().unwrap_or("web");

    let allowed_uris = data.allowed_uris.clone();
    let final_redirect_str = query
        .redirect_uri
        .clone()
        .unwrap_or_else(|| settings.frontend_url.clone());

    let is_cli_localhost = client_type == "cli"
        && (final_redirect_str.starts_with("http://127.0.0.1")
            || final_redirect_str.starts_with("http://localhost"));

    let validated_redirect_uri = if allowed_uris.contains(&final_redirect_str) || is_cli_localhost {
        final_redirect_str
    } else {
        log!([AUTH] => "Invalid redirect_uri specified: {}", final_redirect_str);
        settings.frontend_url.clone()
    };

    let state = format!(
        "{}:{}:{}",
        CsrfToken::new_random().secret(),
        client_type,
        validated_redirect_uri
    );
    let (url, _) = gh_client
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
    let settings = data.settings.clone();
    if settings.github_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid state" }));
    }
    let (client_type, redirect) = (state_parts[1], state_parts[2]);

    let gh_client = data
        .github_oauth_client
        .clone()
        .expect("Missing GitHub OAuth client");

    let token_result = gh_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;
    let token = match token_result {
        Ok(t) => t.access_token().secret().to_string(),
        Err(e) => {
            log!([DEBUG] => "GitHub token exchange failed: {:?}", e);
            return handle_oauth_error(
                &settings,
                client_type,
                "Failed to authenticate with GitHub.",
            );
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
            return handle_oauth_error(
                &settings,
                client_type,
                "Failed to fetch your GitHub profile.",
            );
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
        Ok(user) => {
            if user.is_banned {
                return handle_oauth_error(&settings, client_type, "Your account has been banned.");
            }
            user
        }
        Err(e) => {
            log!([DEBUG] => "GitHub upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return handle_oauth_error(&settings, client_type, message);
            }
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error" }));
        }
    };

    finalize_login(user, client_type, redirect, &data, &req, false).await
}

#[get("/google")]
async fn google_login(
    query: web::Query<AuthLoginQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
    if settings.google_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let client_type = query.client.as_deref().unwrap_or("web");
    let allowed_uris = data.allowed_uris.clone();
    let final_redirect_str = query
        .redirect_uri
        .clone()
        .unwrap_or_else(|| settings.frontend_url.clone());

    let is_cli_localhost = client_type == "cli"
        && (final_redirect_str.starts_with("http://127.0.0.1")
            || final_redirect_str.starts_with("http://localhost"));

    let validated_redirect_uri = if allowed_uris.contains(&final_redirect_str) || is_cli_localhost {
        final_redirect_str
    } else {
        log!([AUTH] => "Invalid redirect_uri specified: {}", final_redirect_str);
        settings.frontend_url.clone()
    };

    let state = format!(
        "{}:{}:{}",
        CsrfToken::new_random().secret(),
        client_type,
        validated_redirect_uri
    );
    let g_client = data
        .google_oauth_client
        .clone()
        .expect("Google OAuth client missing");
    let (url, _) = g_client
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
    let settings = data.settings.clone();
    if settings.google_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid state" }));
    }
    let (client_type, redirect) = (state_parts[1], state_parts[2]);
    let g_client = data
        .google_oauth_client
        .clone()
        .expect("Google OAuth client missing");

    let token_result = g_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;
    let token = match token_result {
        Ok(t) => t.access_token().secret().to_string(),
        Err(e) => {
            log!([DEBUG] => "Google token exchange failed: {:?}", e);
            return handle_oauth_error(
                &settings,
                client_type,
                "Failed to authenticate with Google.",
            );
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
        Ok(user) => user,
        Err(_) => {
            return handle_oauth_error(
                &settings,
                client_type,
                "Failed to fetch your Google profile.",
            );
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
        Ok(user) => {
            if user.is_banned {
                return handle_oauth_error(&settings, client_type, "Your account has been banned.");
            }
            user
        }
        Err(e) => {
            log!([DEBUG] => "Google upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return handle_oauth_error(&settings, client_type, message);
            }
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error" }));
        }
    };
    finalize_login(user, client_type, redirect, &data, &req, false).await
}

#[get("/discord")]
async fn discord_login(
    query: web::Query<AuthLoginQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
    if settings.discord_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let client_type = query.client.as_deref().unwrap_or("web");
    let allowed_uris = data.allowed_uris.clone();
    let final_redirect_str = query
        .redirect_uri
        .clone()
        .unwrap_or_else(|| settings.frontend_url.clone());

    let is_cli_localhost = client_type == "cli"
        && (final_redirect_str.starts_with("http://127.0.0.1")
            || final_redirect_str.starts_with("http://localhost"));

    let validated_redirect_uri = if allowed_uris.contains(&final_redirect_str) || is_cli_localhost {
        final_redirect_str
    } else {
        log!([AUTH] => "Invalid redirect_uri specified: {}", final_redirect_str);
        settings.frontend_url.clone()
    };

    let state = format!(
        "{}:{}:{}",
        CsrfToken::new_random().secret(),
        client_type,
        validated_redirect_uri
    );
    let ds_client = data
        .discord_oauth_client
        .clone()
        .expect("Discord OAuth client missing");
    let (url, _) = ds_client
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
    let settings = data.settings.clone();
    if settings.discord_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let state_parts: Vec<_> = query.state.splitn(3, ':').collect();
    if state_parts.len() != 3 {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid state" }));
    }
    let (client_type, redirect) = (state_parts[1], state_parts[2]);

    let ds_client = data
        .discord_oauth_client
        .clone()
        .expect("Discord OAuth client missing");
    let token_result = ds_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;
    let token = match token_result {
        Ok(t) => t.access_token().secret().to_string(),
        Err(e) => {
            log!([DEBUG] => "Discord token exchange failed: {:?}", e);
            return handle_oauth_error(
                &settings,
                client_type,
                "Failed to authenticate with Discord.",
            );
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
        Ok(user) => user,
        Err(_) => {
            return handle_oauth_error(
                &settings,
                client_type,
                "Failed to fetch your Discord profile.",
            );
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
            return handle_oauth_error(
                &settings,
                client_type,
                "A verified email is required to sign up with Discord.",
            );
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
        Ok(user) => {
            if user.is_banned {
                return handle_oauth_error(&settings, client_type, "Your account has been banned.");
            }
            user
        }
        Err(e) => {
            log!([DEBUG] => "Discord upsert failed: {:?}", e);
            if let sqlx::Error::RowNotFound = e {
                let message = "Your account has been scheduled for deletion. You have 14 days to request recovery by contacting support at support@wayclip.com";
                return handle_oauth_error(&settings, client_type, message);
            }
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Database error" }));
        }
    };
    finalize_login(user, client_type, redirect, &data, &req, false).await
}

#[post("/register")]
async fn register_with_password(
    payload: web::Json<PasswordRegisterPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
    if settings.email_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let min_password_length = settings.min_password_length as usize;
    if payload.password.len() < min_password_length {
        return HttpResponse::BadRequest().json(json!({ "message": format!("Password must be at least {} characters long.", min_password_length) }));
    }
    if !validator::ValidateEmail::validate_email(&payload.email) {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid email format." }));
    }

    let username = &payload.username;
    let is_valid_username = username.len() >= 3
        && username.len() <= 20
        && username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        && !username.starts_with('_')
        && !username.starts_with('-')
        && !username.ends_with('_')
        && !username.ends_with('-')
        && !username.contains(' ');

    if !is_valid_username {
        return HttpResponse::BadRequest().json(
            json!({ "message": "Username must be 3-20 characters long, can contain letters, numbers, underscores, and hyphens, but cannot start or end with them, and cannot contain spaces." }),
        );
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
            tx.rollback().await.ok();
            return HttpResponse::Conflict()
                .json(json!({ "message": "User with this email or username already exists." }));
        }
    };

    if (sqlx::query(
        "INSERT INTO user_credentials (user_id, provider, password_hash) VALUES ($1, 'email', $2)",
    )
    .bind(new_user.id)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await)
        .is_err()
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Could not save credentials." }));
    }

    let verification_token = Uuid::new_v4();
    if (sqlx::query("INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')").bind(verification_token).bind(new_user.id).execute(&mut *tx).await).is_err() {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(json!({ "message": "Could not create verification token." }));
    }

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Database transaction failed." }));
    }

    if let Some(mailer) = data.mailer.clone() {
        if let Err(e) = mailer.send_verification_email(
            new_user.email.as_ref().unwrap(),
            &new_user.username,
            &verification_token,
        ) {
            log!([DEBUG] => "Failed to send verification email: {:?}", e);
        }
    } else {
        log!([DEBUG] => "Mailer not configured, cannot send verification email.");
    }

    HttpResponse::Ok().json(serde_json::json!({ "message": "Registration successful. Please check your email to verify your account." }))
}

#[get("/verify-email/{token}")]
async fn verify_email(token: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let settings = data.settings.clone();
    if settings.email_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
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

    if (sqlx::query!(
        "UPDATE users SET email_verified_at = NOW() WHERE id = $1",
        record.user_id
    )
    .execute(&mut *tx)
    .await)
        .is_err()
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Failed to verify email." }));
    }

    sqlx::query!(
        "DELETE FROM email_verification_tokens WHERE user_id = $1",
        record.user_id
    )
    .execute(&mut *tx)
    .await
    .ok();

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Database transaction failed." }));
    }

    let frontend_url = settings.frontend_url.clone();

    HttpResponse::Found()
        .append_header((LOCATION, format!("{frontend_url}/login?verified=true")))
        .finish()
}

#[post("/resend-verification")]
async fn resend_verification_email(
    payload: web::Json<ResendVerificationPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
    if settings.email_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
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
    if ( sqlx::query("INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')").bind(token).bind(user.id).execute(&mut *tx).await).is_err() {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(json!({ "message": "Could not generate new token." }));
    }

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Database transaction failed." }));
    }

    if let Some(mailer) = data.mailer.clone() {
        mailer
            .send_verification_email(user.email.as_ref().unwrap(), &user.username, &token)
            .ok();
    } else {
        log!([DEBUG] => "Mailer not configured, cannot resend verification email.");
    }

    HttpResponse::Ok().json(success_message)
}

#[post("/login")]
async fn login_with_password(
    req: HttpRequest,
    payload: web::Json<PasswordLoginPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
    if settings.email_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
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

    finalize_login(user, "web", "/", &data, &req, true).await
}

#[post("/forgot-password")]
async fn forgot_password(
    payload: web::Json<ForgotPasswordPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
    if settings.email_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
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

    if let Some(mailer) = data.mailer.clone() {
        if let Err(e) =
            mailer.send_password_reset_email(user.email.as_ref().unwrap(), &user.username, &token)
        {
            log!([DEBUG] => "Failed to send password reset email: {:?}", e);
        }
    } else {
        log!([DEBUG] => "Mailer not configured, cannot send password reset email.");
    }

    HttpResponse::Ok().json(success_message)
}

#[post("/reset-password")]
async fn reset_password(
    payload: web::Json<ResetPasswordPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
    if settings.email_auth_enabled.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let min_password_length = settings.min_password_length as usize;
    if payload.password.len() < min_password_length {
        return HttpResponse::BadRequest().json(json!({ "message": format!("Password must be at least {} characters long.", min_password_length) }));
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
    let app_name = &data.settings.app_name;
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
        Some(app_name.to_string()),
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
                    .choose(&mut rand::rng())
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

    let secret = match user.two_factor_secret.as_ref() {
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
        Secret::Encoded(secret.clone()).to_bytes().unwrap(),
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
        let session_token =
            record_successful_login(&data.db_pool, &user, &req, data.mailer.as_ref()).await;

        let message = if used_recovery_code {
            "2FA validation successful with recovery code."
        } else {
            "2FA validation successful"
        };
        let auth_cookie = build_auth_cookie("session_token", &session_token, None);
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
    let connected_accounts = (sqlx::query_as::<_, (CredentialProvider,)>(
        "SELECT provider FROM user_credentials WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&data.db_pool)
    .await)
        .unwrap_or_default();

    let storage_limit = data
        .tiers
        .get(&user.tier.to_lowercase())
        .map(|t| t.max_storage_bytes)
        .unwrap_or(0);

    let profile = UserProfile {
        user,
        storage_used: stats.total_size.unwrap_or(0),
        storage_limit,
        clip_count: stats.clip_count.unwrap_or(0),
        connected_accounts: connected_accounts.into_iter().map(|(p,)| p).collect(),
    };

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

    if provider_to_unlink == "email" && data.settings.email_auth_enabled.clone().is_none() {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Email authentication is disabled." }));
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
async fn logout(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if let Some(cookie) = req.cookie("session_token") {
        let session_token = cookie.value();
        sqlx::query!(
            "DELETE FROM user_sessions WHERE session_token = $1",
            session_token
        )
        .execute(&data.db_pool)
        .await
        .ok();
    }

    let expiry = actix_web::cookie::time::OffsetDateTime::now_utc() - Duration::days(1);
    let cookie = build_auth_cookie("session_token", "", Some(expiry));
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

    let current_session_token = match req.cookie("session_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            return HttpResponse::BadRequest()
                .json(json!({"message": "Current session not found."}));
        }
    };

    match sqlx::query!(
        "DELETE FROM user_sessions WHERE user_id = $1 AND session_token != $2",
        user_id,
        current_session_token
    )
    .execute(&data.db_pool)
    .await
    {
        Ok(_) => {
            log!([DEBUG] => "User {} logged out all other devices.", user_id);
            HttpResponse::Ok()
                .json(serde_json::json!({ "message": "All other sessions have been logged out." }))
        }
        Err(e) => {
            log!([DEBUG] => "Failed to logout devices for user {}: {:?}", user_id, e);
            HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to log out other devices." }))
        }
    }
}

#[get("/sessions")]
pub async fn get_sessions(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let user_id = match req.extensions().get::<Uuid>() {
        Some(id) => *id,
        None => return HttpResponse::Unauthorized().finish(),
    };

    match session::get_user_sessions(&data.db_pool, user_id).await {
        Ok(sessions) => {
            let session_data: Vec<_> = sessions
                .into_iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "device": session::parse_user_agent(s.user_agent.as_deref().unwrap_or("Unknown")),
                        "last_seen_at": s.last_seen_at,
                        "created_at": s.created_at,
                        "is_current": req.cookie("session_token").map_or(false, |c| c.value() == s.session_token)
                    })
                })
                .collect();
            HttpResponse::Ok().json(session_data)
        }
        Err(e) => {
            log!([DEBUG] => "Failed to fetch sessions for user {}: {:?}", user_id, e);
            HttpResponse::InternalServerError()
                .json(json!({"message": "Could not retrieve sessions."}))
        }
    }
}

#[delete("/sessions/{session_id}")]
pub async fn revoke_session(
    req: HttpRequest,
    path: web::Path<Uuid>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user_id = match req.extensions().get::<Uuid>() {
        Some(id) => *id,
        None => return HttpResponse::Unauthorized().finish(),
    };
    let session_id_to_revoke = path.into_inner();

    match sqlx::query!(
        "DELETE FROM user_sessions WHERE id = $1 AND user_id = $2",
        session_id_to_revoke,
        user_id
    )
    .execute(&data.db_pool)
    .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                HttpResponse::Ok().json(json!({"message": "Session has been revoked."}))
            } else {
                HttpResponse::NotFound().json(json!({"message": "Session not found or you do not have permission to revoke it."}))
            }
        }
        Err(e) => {
            log!([DEBUG] => "Failed to revoke session {} for user {}: {:?}", session_id_to_revoke, user_id, e);
            HttpResponse::InternalServerError()
                .json(json!({"message": "Failed to revoke session."}))
        }
    }
}

#[get("/get-auth-info")]
pub async fn get_auth_info(state: web::Data<AppState>) -> impl Responder {
    let settings = state.settings.clone();
    HttpResponse::Ok().json(json!({
        "discord_auth_enabled": settings.discord_auth_enabled,
        "github_auth_enabled": settings.github_auth_enabled,
        "google_auth_enabled": settings.google_auth_enabled,
        "email_auth_enabled": settings.email_auth_enabled
    }))
}
