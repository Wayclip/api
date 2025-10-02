use serde::Deserialize;
use wayclip_core::log;

#[derive(Deserialize, Clone)]
pub struct Settings {
    pub storage_type: String,
    pub public_url: String,
    pub local_storage_path: Option<String>,

    pub discord_notifications: Option<bool>,
    pub discord_webhook_url: Option<String>,
    pub discord_userid: Option<String>,

    pub sftp_host: Option<String>,
    pub sftp_port: Option<u16>,
    pub sftp_user: Option<String>,
    pub sftp_password: Option<String>,
    pub sftp_remote_path: Option<String>,

    pub payments_enabled: Option<bool>,
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
