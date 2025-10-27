use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;
use wayclip_core::models::UserRole;

#[derive(Serialize, FromRow)]
pub struct UserAdminInfo {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub tier: String,
    pub is_banned: bool,
    pub role: UserRole,
    pub clip_count: i64,
    pub data_used: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ReportedClipInfo {
    pub clip_id: Uuid,
    pub file_name: String,
    pub file_size: i64,
    pub uploader_username: String,
    pub report_token: Uuid,
}

#[derive(serde::Deserialize)]
pub struct UpdateRolePayload {
    pub role: UserRole,
}

#[derive(serde::Deserialize)]
pub struct UpdateTierPayload {
    pub tier: String,
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct FullUserDetails {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub tier: String,
    pub role: UserRole,
    pub is_banned: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub two_factor_enabled: bool,
    pub subscription_status: Option<String>,
    pub current_period_end: Option<chrono::DateTime<chrono::Utc>>,
    #[sqlx(json)]
    pub connected_providers: serde_json::Value,
}

#[derive(Serialize)]
pub struct AdminDashboardData {
    pub users: Vec<UserAdminInfo>,
    pub reported_clips: Vec<ReportedClipInfo>,
    pub total_data_usage: i64,
}
