use crate::mailer::Mailer;
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
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use sqlx::PgPool;
use std::collections::HashMap;
use std::fs as std_fs;
use std::sync::Arc;
use std::time::Duration;
use stripe::Client;
use tracing_actix_web::TracingLogger;
use wayclip_core::log;
use wayclip_core::models::TierConfig;

mod admin_handler;
mod auth_handler;
mod clip_handler;
mod db;
mod jwt;
mod mailer;
mod middleware;
mod models;
mod settings;
mod storage;
mod stripe_handler;

#[derive(Clone)]
pub struct AppState {
    db_pool: PgPool,
    github_oauth_client: Option<BasicClient>,
    google_oauth_client: Option<BasicClient>,
    discord_oauth_client: Option<BasicClient>,
    allowed_uris: Vec<String>,
    storage: Arc<dyn Storage>,
    mailer: Option<mailer::Mailer>,
    tiers: Arc<HashMap<String, TierConfig>>,
    settings: Arc<Settings>,
}

async fn seed_initial_admins(db_pool: &PgPool, settings: &Settings) {
    if let Some(admin_emails_str) = &settings.initial_admin_emails {
        if admin_emails_str.is_empty() {
            return;
        }

        let admin_emails: Vec<&str> = admin_emails_str.split(',').map(|e| e.trim()).collect();
        log!([DEBUG] => "Attempting to seed initial admins for emails: {:?}", admin_emails);

        let result = sqlx::query("UPDATE users SET role = 'admin' WHERE email = ANY($1)")
            .bind(&admin_emails)
            .execute(db_pool)
            .await;

        match result {
            Ok(query_result) => {
                if query_result.rows_affected() > 0 {
                    log!([DEBUG] => "Seeded initial admins. {} users affected.", query_result.rows_affected());
                }
            }
            Err(e) => {
                log!([DEBUG] => "Failed to seed initial admins: {:?}", e);
            }
        }
    }
}

async fn init_plans(pool: &PgPool, settings: &Settings) {
    let plan_count: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM plans")
        .fetch_one(pool)
        .await
    {
        Ok(count) => count,
        Err(e) => {
            log!([DEBUG] => "Failed to check for existing plans in database: {}", e);
            return;
        }
    };

    if plan_count == 0 {
        log!([DEBUG] => "No plans found in the database. Initializing from settings...");

        let json_config = settings
            .tiers_json
            .clone()
            .unwrap_or_else(|| "[]".to_string());
        if json_config == "[]" {
            log!([DEBUG] => "TIERS_JSON is empty. No plans will be initialized.");
            return;
        }

        let tiers_to_insert: Vec<TierConfig> = match serde_json::from_str(&json_config) {
            Ok(parsed) => parsed,
            Err(e) => {
                log!([DEBUG]=>
                    "Failed to parse TIERS_JSON: {e}. Please check the format.",
                );
                return;
            }
        };

        for tier in tiers_to_insert {
            let result = sqlx::query(
                r#"
                INSERT INTO plans (
                    name, max_storage_bytes, stripe_price_id, display_price,
                    display_frequency, description, display_features, is_popular
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                "#,
            )
            .bind(&tier.name)
            .bind(tier.max_storage_bytes as i64)
            .bind(&tier.stripe_price_id)
            .bind(&tier.display_price)
            .bind(&tier.display_frequency)
            .bind(&tier.description)
            .bind(&tier.display_features)
            .bind(&tier.is_popular)
            .execute(pool)
            .await;

            match result {
                Ok(_) => log!([DEBUG] => "Successfully inserted plan: '{}'", tier.name),
                Err(e) => log!([DEBUG] => "Failed to insert plan '{}': {}", tier.name, e),
            }
        }
    } else {
        log!([DEBUG] =>
            "Database already contains {} plans. Skipping initialization.",
            plan_count
        );
    }
}

async fn load_tiers_from_db(pool: &PgPool) -> HashMap<String, TierConfig> {
    sqlx::query_as::<_, TierConfig>("SELECT * FROM plans")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|tier| (tier.name.clone(), tier))
        .collect()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut github_oauth_client: Option<BasicClient> = None;
    let mut google_oauth_client: Option<BasicClient> = None;
    let mut discord_oauth_client: Option<BasicClient> = None;
    let mut mailer: Option<Mailer> = None;
    let mut stripe_client: Option<stripe::Client> = None;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    log!([DEBUG] => "Logger initialized. Starting up Wayclip API...");

    let settings = Settings::new().expect("Failed to load configuration");
    log!([DEBUG] => "Configuration loaded successfully.");

    let payments_enabled = settings.payments_enabled.unwrap_or(false);
    let backend_url = settings.backend_url.clone();

    let pool = db::create_pool(&settings.database_url)
        .await
        .expect("Failed to create database pool.");
    log!([DEBUG] => "Database pool created successfully.");

    init_plans(&pool, &settings).await;
    let tiers = Arc::new(load_tiers_from_db(&pool).await);
    log!([DEBUG] => "Tier limits loaded from database.");

    seed_initial_admins(&pool, &settings).await;

    if settings.github_auth_enabled.is_some() {
        if let (Some(client_id), Some(client_secret)) =
            (&settings.github_client_id, &settings.github_client_secret)
        {
            github_oauth_client = Some(
                BasicClient::new(
                    ClientId::new(client_id.clone()),
                    Some(ClientSecret::new(client_secret.clone())),
                    AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
                    Some(
                        TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                            .unwrap(),
                    ),
                )
                .set_redirect_uri(
                    RedirectUrl::new(format!("{backend_url}/auth/github/callback")).unwrap(),
                ),
            );
        } else {
            panic!(
                "GitHub auth is enabled, but GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET is missing."
            );
        }
    }

    if settings.google_auth_enabled.is_some() {
        if let (Some(client_id), Some(client_secret)) =
            (&settings.google_client_id, &settings.google_client_secret)
        {
            google_oauth_client = Some(
                BasicClient::new(
                    ClientId::new(client_id.clone()),
                    Some(ClientSecret::new(client_secret.clone())),
                    AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                        .unwrap(),
                    Some(
                        TokenUrl::new("https://www.googleapis.com/oauth2/v4/token".to_string())
                            .unwrap(),
                    ),
                )
                .set_redirect_uri(
                    RedirectUrl::new(format!("{backend_url}/auth/google/callback")).unwrap(),
                ),
            );
        } else {
            panic!(
                "Google auth is enabled, but GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET is missing."
            );
        }
    }

    if settings.discord_auth_enabled.is_some() {
        if let (Some(client_id), Some(client_secret)) =
            (&settings.discord_client_id, &settings.discord_client_secret)
        {
            discord_oauth_client = Some(
                BasicClient::new(
                    ClientId::new(client_id.clone()),
                    Some(ClientSecret::new(client_secret.clone())),
                    AuthUrl::new("https://discord.com/api/oauth2/authorize".to_string()).unwrap(),
                    Some(
                        TokenUrl::new("https://discord.com/api/oauth2/token".to_string()).unwrap(),
                    ),
                )
                .set_redirect_uri(
                    RedirectUrl::new(format!("{backend_url}/auth/discord/callback")).unwrap(),
                ),
            );
        } else {
            panic!("Discord auth is enabled, but DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET is missing.");
        }
    }

    if payments_enabled {
        if let Some(key) = &settings.stripe_secret_key {
            stripe_client = Some(Client::new(key.clone()));
        } else {
            panic!("Payments are enabled, but STRIPE_SECRET_KEY is missing.");
        }
    }

    if settings.email_auth_enabled.is_some() {
        mailer = Some(Mailer::new(&settings));
    }

    log!([AUTH] => "OAuth2 configured with Redirect URL: {backend_url}/auth/callback");

    let storage: Arc<dyn Storage> = match settings.storage_type.as_str() {
        "LOCAL" => Arc::new(LocalStorage::new(&settings)),
        "SFTP" => Arc::new(
            SftpStorage::new(&settings)
                .expect("Failed to create SFTP Storage with connection pool"),
        ),
        _ => panic!("Invalid STORAGE_TYPE specified"),
    };
    log!([DEBUG] => "Storage backend initialized: {}", settings.storage_type);

    if settings.storage_type == "LOCAL" {
        let local_path = settings
            .local_storage_path
            .clone()
            .unwrap_or_else(|| "./uploads".to_string());
        std_fs::create_dir_all(&local_path).expect("Could not create local storage directory");
    }
    let frontend_url = settings.frontend_url.clone();

    let allowed_uris: Vec<String> = settings
        .allow_redirect_uris
        .clone()
        .unwrap_or_default()
        .split(",")
        .map(String::from)
        .collect();

    let app_state = AppState {
        db_pool: pool,
        github_oauth_client,
        google_oauth_client,
        discord_oauth_client,
        allowed_uris,
        storage,
        tiers,
        settings: Arc::new(settings.clone()), // Perhaps split into separate app_data's
        mailer,
    };

    let backend = InMemoryBackend::builder().build();

    log!([DEBUG] => "Starting Actix web server on 0.0.0.0:8080...");

    HttpServer::new(move || {
        let frontend_url_clone = frontend_url.clone();
        let backend_url_clone = backend_url.clone();

        let cors = Cors::default()
            .allowed_origin_fn(move |origin: &HeaderValue, _req_head: &RequestHead| {
                if let Ok(s) = origin.to_str() {
                    let allowed_origins = [
                        frontend_url_clone.trim_end_matches('/'),
                        backend_url_clone.trim_end_matches('/'),
                    ];
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
                    .service(auth_handler::forgot_password)
                    .service(auth_handler::reset_password)
                    .service(auth_handler::resend_verification_email)
                    .service(auth_handler::two_factor_authenticate),
            )
            .service(
                web::scope("/api")
                    .wrap(middleware::Auth)
                    .service(auth_handler::logout)
                    .service(auth_handler::logout_all_devices)
                    .service(clip_handler::get_clips_index)
                    .service(clip_handler::delete_clip)
                    .service(auth_handler::get_me)
                    .service(auth_handler::delete_account)
                    .service(auth_handler::unlink_oauth_provider)
                    .service(auth_handler::two_factor_setup)
                    .service(auth_handler::two_factor_verify)
                    .service(stripe_handler::create_checkout_session)
                    .service(stripe_handler::create_customer_portal_session)
                    .service(stripe_handler::verify_checkout_session)
                    .service(stripe_handler::cancel_subscription)
                    .service(
                        web::scope("/share")
                            .wrap(ratelimiter)
                            .service(clip_handler::share_clip_begin)
                            .service(clip_handler::share_clip_upload),
                    ),
            )
            .service(stripe_handler::stripe_webhook)
            .service(
                web::scope("/admin")
                    .wrap(middleware::AdminAuth)
                    .wrap(middleware::Auth)
                    .service(admin_handler::ban_user_and_ip)
                    .service(admin_handler::remove_video)
                    .service(admin_handler::get_admin_dashboard)
                    .service(admin_handler::get_user_details)
                    .service(admin_handler::update_user_role)
                    .service(admin_handler::update_user_tier)
                    .service(admin_handler::delete_clip_by_admin)
                    .service(admin_handler::ban_user)
                    .service(admin_handler::ignore_report)
                    .service(admin_handler::get_user_clips)
                    .service(admin_handler::delete_user)
                    .service(admin_handler::unban_user),
            )
            .service(clip_handler::serve_clip)
            .service(clip_handler::serve_clip_raw)
            .service(clip_handler::serve_clip_oembed)
            .service(clip_handler::report_clip)
            .service(clip_handler::get_app_info)
            .service(auth_handler::get_auth_info)
            .service(stripe_handler::get_payment_info)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
