use crate::settings::Settings;
use crate::storage::{LocalStorage, SftpStorage, Storage};
use actix_cors::Cors;
use actix_extensible_rate_limit::{
    backend::{memory::InMemoryBackend, SimpleInputFunctionBuilder},
    RateLimiter,
};
use actix_web::dev::RequestHead;
use actix_web::http::header::HeaderValue;
use actix_web::{web, App, HttpServer};
use dotenvy::dotenv;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use sqlx::PgPool;
use std::collections::HashMap;
use std::env;
use std::fs as std_fs;
use std::sync::Arc;
use std::time::Duration;
use stripe::Client;
use tracing_actix_web::TracingLogger;
use wayclip_core::log;
use wayclip_core::models::SubscriptionTier;

mod admin_handler;
mod auth_handler;
mod clip_handler;
mod db;
mod jwt;
mod mailer;
mod middleware;
mod settings;
mod storage;
mod stripe_handler;

#[derive(Clone)]
pub struct AppState {
    db_pool: PgPool,
    github_oauth_client: BasicClient,
    google_oauth_client: BasicClient,
    discord_oauth_client: BasicClient,
    storage: Arc<dyn Storage>,
    tier_limits: Arc<HashMap<SubscriptionTier, i64>>,
    mailer: mailer::Mailer,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    log!([DEBUG] => "Logger initialized. Starting up Wayclip API...");

    let config = Settings::new().expect("Failed to load configuration");
    log!([DEBUG] => "Configuration loaded successfully.");

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redirect_uri = env::var("REDIRECT_URL").expect("REDIRECT_URL must be set");

    let pool = db::create_pool(&database_url)
        .await
        .expect("Failed to create database pool.");
    log!([DEBUG] => "Database pool created successfully.");

    let github_oauth_client = BasicClient::new(
        ClientId::new(env::var("GITHUB_CLIENT_ID").expect("Missing GITHUB_CLIENT_ID")),
        Some(ClientSecret::new(
            env::var("GITHUB_CLIENT_SECRET").expect("Missing GITHUB_CLIENT_SECRET"),
        )),
        AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
        Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(format!("{}/auth/github/callback", redirect_uri)).unwrap());

    let google_oauth_client = BasicClient::new(
        ClientId::new(env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID")),
        Some(ClientSecret::new(
            env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET"),
        )),
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://www.googleapis.com/oauth2/v4/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(format!("{}/auth/google/callback", redirect_uri)).unwrap());

    let discord_oauth_client = BasicClient::new(
        ClientId::new(env::var("DISCORD_CLIENT_ID").expect("Missing DISCORD_CLIENT_ID")),
        Some(ClientSecret::new(
            env::var("DISCORD_CLIENT_SECRET").expect("Missing DISCORD_CLIENT_SECRET"),
        )),
        AuthUrl::new("https://discord.com/api/oauth2/authorize".to_string()).unwrap(),
        Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(format!("{}/auth/discord/callback", redirect_uri)).unwrap());

    let stripe_secret_key = env::var("STRIPE_SECRET_KEY").expect("Missing STRIPE_SECRET_KEY");
    let redirect_url =
        RedirectUrl::new(format!("{redirect_uri}/auth/callback").to_string()).unwrap();

    log!([AUTH] => "OAuth2 configured with Redirect URL: {redirect_url:?}");

    let stripe_client = Client::new(stripe_secret_key);

    let storage: Arc<dyn Storage> = match config.storage_type.as_str() {
        "LOCAL" => Arc::new(LocalStorage::new(&config)),
        "SFTP" => Arc::new(
            SftpStorage::new(&config).expect("Failed to create SFTP Storage with connection pool"),
        ),
        _ => panic!("Invalid STORAGE_TYPE specified"),
    };
    log!([DEBUG] => "Storage backend initialized: {}", config.storage_type);

    if config.storage_type == "LOCAL" {
        let local_path = config
            .local_storage_path
            .clone()
            .unwrap_or_else(|| "./uploads".to_string());
        std_fs::create_dir_all(&local_path).expect("Could not create local storage directory");
    }

    let tier_limits = Arc::new(config.get_tier_limits());
    log!([DEBUG] => "Tier limits loaded.");

    let app_state = AppState {
        db_pool: pool,
        github_oauth_client,
        google_oauth_client,
        discord_oauth_client,
        storage,
        tier_limits,
        mailer: mailer::Mailer::new(),
    };

    let app_settings = web::Data::new(config.clone());
    let backend = InMemoryBackend::builder().build();

    log!([DEBUG] => "Starting Actix web server on 0.0.0.0:8080...");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin: &HeaderValue, _req_head: &RequestHead| {
                let allowed_origins = [
                    "http://localhost:3000",
                    "https://wayclip.com",
                    "https://dash.wayclip.com",
                ];
                if let Ok(s) = origin.to_str() {
                    allowed_origins.contains(&s)
                } else {
                    false
                }
            })
            .allowed_methods(vec!["GET", "POST", "DELETE"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::CONTENT_TYPE,
            ])
            .supports_credentials()
            .max_age(3600);

        let input = SimpleInputFunctionBuilder::new(Duration::from_secs(3600), 20)
            .real_ip_key()
            .build();
        let ratelimiter = RateLimiter::builder(backend.clone(), input)
            .add_headers()
            .build();

        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .app_data(app_settings.clone())
            .app_data(web::Data::new(stripe_client.clone()))
            .wrap(cors)
            .wrap(TracingLogger::default())
            .service(
                web::scope("/auth")
                    .service(auth_handler::github_login)
                    .service(auth_handler::github_callback)
                    .service(auth_handler::google_login)
                    .service(auth_handler::google_callback)
                    .service(auth_handler::discord_login)
                    .service(auth_handler::discord_callback)
                    .service(auth_handler::register_with_password)
                    .service(auth_handler::login_with_password)
                    .service(auth_handler::verify_email)
                    .service(auth_handler::resend_verification_email)
                    .service(auth_handler::logout)
                    .service(auth_handler::two_factor_authenticate),
            )
            .service(
                web::scope("/api")
                    .wrap(middleware::Auth)
                    .service(clip_handler::get_clips_index)
                    .service(clip_handler::delete_clip)
                    .service(auth_handler::get_me)
                    .service(auth_handler::delete_account)
                    .service(auth_handler::unlink_oauth_provider)
                    .service(auth_handler::two_factor_setup)
                    .service(auth_handler::two_factor_verify)
                    .service(stripe_handler::create_checkout_session)
                    .service(
                        web::scope("")
                            .wrap(ratelimiter)
                            .service(clip_handler::share_clip),
                    ),
            )
            .service(stripe_handler::stripe_webhook)
            .service(
                web::scope("/admin")
                    .service(admin_handler::ban_user_and_ip)
                    .service(admin_handler::remove_video),
            )
            .service(clip_handler::serve_clip)
            .service(clip_handler::serve_clip_raw)
            .service(clip_handler::serve_clip_oembed)
            .service(clip_handler::report_clip)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
