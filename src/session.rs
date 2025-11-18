use actix_web::HttpRequest;
use sqlx::PgPool;
use uaparser::{Parser, UserAgentParser};
use uuid::Uuid;

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub user_agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
}

pub fn get_user_agent(req: &HttpRequest) -> String {
    req.headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string()
}

pub fn parse_user_agent(user_agent_string: &str) -> String {
    let ua_parser =
        UserAgentParser::from_yaml("../assets/regexes.yaml").expect("Failed to create parser");
    let client = ua_parser.parse(user_agent_string);

    if client.os.family == "Other"
        && client.user_agent.family == "Other"
        && client.device.family == "Other"
    {
        return "Unknown Device".to_string();
    }

    let os = {
        let family = client.os.family.to_string();
        if family != "Other" {
            let mut os_string = family;
            if let Some(major) = client.os.major {
                os_string.push(' ');
                os_string.push_str(&major);
            }
            os_string
        } else {
            "Unknown OS".to_string()
        }
    };

    let browser = {
        let family = client.user_agent.family.to_string();
        if family != "Other" {
            let mut browser_string = family;
            if let Some(major) = client.user_agent.major {
                browser_string.push(' ');
                browser_string.push_str(&major);
            }
            browser_string
        } else {
            "Unknown Browser".to_string()
        }
    };

    format!("{} on {}", browser, os)
}

pub async fn get_user_sessions(db: &PgPool, user_id: Uuid) -> Result<Vec<Session>, sqlx::Error> {
    sqlx::query_as!(
        Session,
        "SELECT id, user_id, session_token, user_agent, created_at, last_seen_at FROM user_sessions WHERE user_id = $1 ORDER BY last_seen_at DESC",
        user_id
    )
    .fetch_all(db)
    .await
}
