use serde::Deserialize;
use wayclip_core::log;

#[derive(Deserialize, Clone)]
pub struct Settings {
    pub backend_url: String,
    pub frontend_url: String,

    pub app_name: String,
    pub default_avatar_url: Option<String>,
    pub upload_limit_bytes: Option<u64>,
    pub database_url: String,

    pub discord_notifications: Option<bool>,
    pub discord_webhook_url: Option<String>,
    pub discord_userid: Option<String>,

    pub initial_admin_emails: Option<String>,
    pub min_password_length: u16,

    pub jwt_secret: String,
    pub allow_redirect_uris: Option<String>,

    pub github_auth_enabled: Option<bool>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,

    pub discord_auth_enabled: Option<bool>,
    pub discord_client_id: Option<String>,
    pub discord_client_secret: Option<String>,

    pub google_auth_enabled: Option<bool>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,

    pub storage_type: String,
    pub local_storage_path: Option<String>,
    pub sftp_host: Option<String>,
    pub sftp_port: Option<u16>,
    pub sftp_user: Option<String>,
    pub sftp_password: Option<String>,
    pub sftp_remote_path: Option<String>,

    pub email_auth_enabled: Option<bool>,
    pub smtp_connect_host: Option<String>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_user: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from_address: Option<String>,

    pub payments_enabled: Option<bool>,
    pub tiers_json: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    pub stripe_secret_key: Option<String>,
    pub stripe_mode: Option<String>,
    pub stripe_locale: Option<String>,
    pub stripe_enable_consent_collection: Option<bool>,
    pub stripe_allow_promocodes: Option<bool>,
}

impl Settings {
    pub fn new() -> Result<Self, config::ConfigError> {
        log!([DEBUG] => "Loading settings from environment variables...");
        let config = config::Config::builder()
            .add_source(config::Environment::default())
            .build()?;
        config.try_deserialize()
    }
}

// TIERS_JSON='[
//   {"name":"Free","max_storage_bytes":2147483648,"stripe_price_id":null},
//   {"name":"Basic","max_storage_bytes":53687091200,"stripe_price_id":"price_1RyAeACHhODgeVy2qiWoIKeZ"},
//   {"name":"Plus","max_storage_bytes":214748364800,"stripe_price_id":"price_1RyAerCHhODgeVy2u6Sbj5GU"},
//   {"name":"Pro","max_storage_bytes":1099511627776,"stripe_price_id":"price_1RyAfFCHhODgeVy2CwUk9Oap"}
// ]'
