use crate::{jwt, AppState};
use actix_web::{
    cookie::{Cookie, SameSite},
    get,
    http::header::LOCATION,
    web, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use oauth2::reqwest::async_http_client;
use oauth2::{AuthorizationCode, CsrfToken, Scope, TokenResponse};
use uuid::Uuid;
use wayclip_core::log;
use wayclip_core::models::{GitHubUser, User, UserProfile};

#[derive(serde::Deserialize)]
pub struct AuthLoginQuery {
    client: Option<String>,
    redirect_uri: Option<String>,
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

    log!([AUTH] => "GitHub login initiated for client: '{}' with final redirect: '{}'", client_type, final_redirect_str);

    let csrf_token = CsrfToken::new_random();

    let state_with_client = format!(
        "{}:{}:{}",
        csrf_token.secret(),
        client_type,
        final_redirect_str
    );
    let csrf_state = CsrfToken::new(state_with_client);
    log!([DEBUG] => "Generated CSRF state for auth flow.");

    let (authorize_url, _csrf_state) = data
        .oauth_client
        .clone()
        .authorize_url(|| csrf_state)
        .add_scope(Scope::new("read:user".to_string()))
        .url();

    log!([AUTH] => "Redirecting user to GitHub authorize URL.");
    HttpResponse::Found()
        .append_header((LOCATION, authorize_url.to_string()))
        .finish()
}

#[derive(serde::Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[get("/callback")]
async fn github_callback(
    query: web::Query<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    log!([AUTH] => "GitHub callback received. Code: '{}', State: '{}'", query.code, query.state);
    let state_parts: Vec<&str> = query.state.splitn(3, ':').collect();

    if state_parts.len() != 3 {
        log!([AUTH] => "ERROR: Invalid state format received. Parts count: {}", state_parts.len());
        return HttpResponse::BadRequest().body("Invalid state format.");
    }

    let client_type = state_parts[1];
    let final_redirect_str = state_parts[2];
    log!([AUTH] => "Parsed state. Client type: '{}', Final redirect: '{}'", client_type, final_redirect_str);

    let code = AuthorizationCode::new(query.code.clone());

    log!([DEBUG] => "Attempting to exchange authorization code for access token...");
    let token_res = data
        .oauth_client
        .clone()
        .exchange_code(code)
        .request_async(async_http_client)
        .await;

    let access_token = match token_res {
        Ok(token) => {
            log!([AUTH] => "Successfully exchanged code for access token.");
            token.access_token().secret().to_string()
        }
        Err(e) => {
            log!([AUTH] => "ERROR: Failed to exchange code for token: {:?}", e);
            return HttpResponse::InternalServerError().body(format!("Error: {e}"));
        }
    };

    let client = reqwest::Client::new();
    log!([DEBUG] => "Fetching user profile from GitHub...");
    let github_user: GitHubUser = match client
        .get("https://api.github.com/user")
        .header("User-Agent", "wayclip-api")
        .bearer_auth(&access_token)
        .send()
        .await
    {
        Ok(res) => match res.json::<GitHubUser>().await {
            Ok(user) => {
                log!([AUTH] => "Successfully fetched GitHub user: {}", user.login);
                user
            }
            Err(e) => {
                log!([AUTH] => "ERROR: Failed to parse GitHub user JSON: {:?}", e);
                return HttpResponse::InternalServerError().body("Failed to parse GitHub user");
            }
        },
        Err(e) => {
            log!([AUTH] => "ERROR: Failed to fetch GitHub user: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to fetch GitHub user");
        }
    };

    log!([DEBUG] => "Upserting user into database...");
    let user = match sqlx::query_as::<_, User>(
        "INSERT INTO users (github_id, username, avatar_url) VALUES ($1, $2, $3)
         ON CONFLICT (github_id) DO UPDATE SET username = $2, avatar_url = $3
         RETURNING *",
    )
    .bind(github_user.id)
    .bind(&github_user.login)
    .bind(github_user.avatar_url.as_deref())
    .fetch_one(&data.db_pool)
    .await
    {
        Ok(user) => {
            log!([AUTH] => "Successfully upserted user. DB ID: {}", user.id);
            user
        }
        Err(e) => {
            log!([AUTH] => "ERROR: Database upsert failed: {:?}", e);
            return HttpResponse::InternalServerError().body(format!("Database error: {e}"));
        }
    };

    log!([DEBUG] => "Creating JWT for user...");
    let jwt = match jwt::create_jwt(user.id) {
        Ok(token) => {
            log!([AUTH] => "Successfully created JWT.");
            token
        }
        Err(e) => {
            log!([AUTH] => "ERROR: Failed to create JWT: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to create token");
        }
    };

    if client_type == "cli" {
        let deep_link = format!("{final_redirect_str}?token={jwt}");
        log!([AUTH] => "Redirecting CLI client to: {}", deep_link);
        HttpResponse::Found()
            .append_header((LOCATION, deep_link))
            .finish()
    } else if client_type == "tauri" {
        let deep_link = format!("wayclip://auth/callback?token={jwt}");
        log!([AUTH] => "Redirecting Tauri client to: {}", deep_link);
        HttpResponse::Found()
            .append_header((LOCATION, deep_link))
            .finish()
    } else {
        log!([AUTH] => "Redirecting web client and setting cookie.");
        let mut response = HttpResponse::Found();
        response.append_header((LOCATION, final_redirect_str));
        response.cookie(
            Cookie::build("token", jwt)
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::Lax)
                .finish(),
        );
        response.finish()
    }
}

#[get("/me")]
pub async fn get_me(req: HttpRequest) -> HttpResponse {
    log!([AUTH] => "/me endpoint called.");
    if let Some(user_id) = req.extensions().get::<Uuid>() {
        log!([DEBUG] => "Authenticated user ID from token: {}", user_id);
        let data: &web::Data<AppState> = req.app_data().unwrap();

        let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(*user_id)
            .fetch_one(&data.db_pool)
            .await
        {
            Ok(user) => user,
            Err(_) => {
                log!([AUTH] => "User ID {} from token not found in database.", user_id);
                return HttpResponse::NotFound().body("User not found");
            }
        };

        let stats = match sqlx::query!(
            "SELECT COALESCE(SUM(file_size), 0)::BIGINT as total_size, COUNT(*) as clip_count FROM clips WHERE user_id = $1",
            user_id
        )
        .fetch_one(&data.db_pool)
        .await {
            Ok(s) => s,
            Err(_) => return HttpResponse::InternalServerError().body("Could not fetch user stats"),
        };

        let storage_limit = data.tier_limits.get(&user.tier).cloned().unwrap_or(0);

        let user_profile = UserProfile {
            user,
            storage_used: stats.total_size.unwrap_or(0),
            storage_limit,
            clip_count: stats.clip_count.unwrap_or(0),
        };
        log!([AUTH] => "Successfully fetched profile for user '{}'.", user_profile.user.username);
        HttpResponse::Ok().json(user_profile)
    } else {
        log!([AUTH] => "Unauthorized access to /me endpoint (no user ID in request extensions).");
        HttpResponse::Unauthorized().finish()
    }
}
