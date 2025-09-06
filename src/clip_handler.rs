use crate::{settings::Settings, AppState};
use actix_multipart::Multipart;
use actix_web::{
    delete, get, http::header::ContentType, post, web, Error, HttpMessage, HttpRequest,
    HttpResponse, Responder,
};
use chrono::{DateTime, Utc};
use futures_util::stream::StreamExt;
use redis::AsyncCommands;
use uuid::Uuid;
use wayclip_core::log;
use wayclip_core::models::{Clip, HostedClipInfo, User};

const MAX_FILE_SIZE: usize = 1_073_741_824;
const CACHE_TTL_SECONDS: u64 = 3600;

#[post("/share")]
pub async fn share_clip(
    req: HttpRequest,
    mut payload: Multipart,
    data: web::Data<AppState>,
    settings: web::Data<Settings>,
) -> Result<HttpResponse, Error> {
    log!([DEBUG] => "Received clip share request.");
    let user_id = req
        .extensions()
        .get::<Uuid>()
        .cloned()
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Not authenticated"))?;
    log!([DEBUG] => "Share request authenticated for user ID: {}", user_id);

    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&data.db_pool)
        .await
        .map_err(|_| actix_web::error::ErrorNotFound("User not found"))?;

    if user.is_banned {
        log!([DEBUG] => "User '{}' is banned. Rejecting share.", user.username);
        return Err(actix_web::error::ErrorForbidden(
            "This account is suspended.",
        ));
    }

    let tier_limit = data.tier_limits.get(&user.tier).cloned().unwrap_or(0);

    let current_usage: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(file_size), 0)::BIGINT FROM clips WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&data.db_pool)
    .await
    .unwrap_or(0);

    log!([DEBUG] => "User '{}' storage usage: {} / {}", user.username, current_usage, tier_limit);

    if let Some(item) = payload.next().await {
        let mut field = item?;
        let filename = field
            .content_disposition()
            .and_then(|cd| cd.get_filename())
            .unwrap_or("clip.mp4")
            .to_string();
        log!([DEBUG] => "Processing uploaded file: '{}'", filename);

        let mut file_data = Vec::new();
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            if file_data.len() + data.len() > MAX_FILE_SIZE {
                return Err(actix_web::error::ErrorPayloadTooLarge(format!(
                    "File size cannot exceed {MAX_FILE_SIZE} bytes",
                )));
            }
            file_data.extend_from_slice(&data);
        }

        let file_size = file_data.len() as i64;
        log!([DEBUG] => "File size is {} bytes.", file_size);
        if current_usage + file_size > tier_limit {
            log!([DEBUG] => "Storage limit exceeded for user '{}'. Rejecting upload.", user.username);
            return Err(actix_web::error::ErrorForbidden(
                "Storage limit exceeded for your subscription tier.",
            ));
        }

        log!([DEBUG] => "Uploading file to storage backend...");
        let storage_path = data
            .storage
            .upload(&filename, file_data.clone())
            .await
            .map_err(|e| {
                log!([DEBUG] => "ERROR: Storage upload failed: {:?}", e);
                actix_web::error::ErrorInternalServerError("Failed to upload file.")
            })?;
        log!([DEBUG] => "File uploaded successfully. Storage path: '{}'", storage_path);

        log!([DEBUG] => "Inserting clip metadata into database...");
        let new_clip: Clip = sqlx::query_as(
            "INSERT INTO clips (user_id, file_name, file_size, public_url) VALUES ($1, $2, $3, $4) RETURNING *",
        )
        .bind(user_id)
        .bind(&filename)
        .bind(file_size)
        .bind(&storage_path)
        .fetch_one(&data.db_pool)
        .await
        .map_err(|e| {
            log!([DEBUG] => "ERROR: DB insert failed: {:?}", e);
            actix_web::error::ErrorInternalServerError("Failed to save clip metadata.")
        })?;
        log!([DEBUG] => "Clip metadata saved to DB. Clip ID: {}", new_clip.id);

        let redis_pool = data.redis_pool.clone();
        let clip_id_for_cache = new_clip.id;
        tokio::spawn(async move {
            log!([DEBUG] => "CACHE_WARM: Starting background cache for new clip {}", clip_id_for_cache);
            if let Ok(mut conn) = redis_pool.get().await {
                let cache_key = format!("clip_raw:{}", clip_id_for_cache);
                let result: redis::RedisResult<()> =
                    conn.set_ex(&cache_key, &file_data, CACHE_TTL_SECONDS).await;
                if let Err(e) = result {
                    log!([DEBUG] => "ERROR: CACHE_WARM: Redis SETEX failed for key '{}': {:?}", cache_key, e);
                } else {
                    log!([DEBUG] => "CACHE_WARM: Successfully cached {} bytes for clip {}.", file_data.len(), clip_id_for_cache);
                }
            } else {
                log!([DEBUG] => "ERROR: CACHE_WARM: Could not get Redis connection for caching.");
            }
        });

        let response_url = format!("{}/clip/{}", settings.public_url, new_clip.id);
        Ok(HttpResponse::Ok().json(serde_json::json!({ "url": response_url })))
    } else {
        Err(actix_web::error::ErrorBadRequest("No file uploaded."))
    }
}

struct ClipDetails {
    id: Uuid,
    file_name: String,
    created_at: DateTime<Utc>,
    username: String,
    avatar_url: Option<String>,
}

#[get("/clip/{id}")]
pub async fn serve_clip(
    req: HttpRequest,
    id: web::Path<Uuid>,
    data: web::Data<AppState>,
    settings: web::Data<Settings>,
) -> impl Responder {
    log!([DEBUG] => "Serving clip page for ID: {}", *id);

    let clip_details = match sqlx::query_as!(
        ClipDetails,
        r#"
        SELECT
            c.id,
            c.file_name,
            c.created_at,
            u.username,
            u.avatar_url
        FROM clips c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = $1
        "#,
        *id
    )
    .fetch_one(&data.db_pool)
    .await
    {
        Ok(details) => details,
        Err(_) => {
            log!([WARN] => "Clip with ID {} not found.", *id);
            let template = include_str!("../assets/not_found.html");
            return HttpResponse::NotFound()
                .content_type("text/html; charset=utf-8")
                .body(template);
        }
    };

    let clip_url = format!("{}/clip/{}", settings.public_url, clip_details.id);
    let raw_url = format!("{}/clip/{}/raw", settings.public_url, clip_details.id);
    let report_url = format!("/clip/{}/report", clip_details.id);
    let uploader_avatar = clip_details
        .avatar_url
        .clone()
        .unwrap_or_else(|| "https://avatars.githubusercontent.com/u/1024025?v=4".to_string());
    let formatted_date = clip_details.created_at.format("%B %e, %Y").to_string();

    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or("");
    let is_bot = ["Discordbot", "Twitterbot", "facebookexternalhit"]
        .iter()
        .any(|bot| user_agent.contains(bot));

    let html_body = if is_bot {
        log!([DEBUG] => "Bot detected ('{}'), serving meta tags.", user_agent);
        let template = include_str!("../assets/embed.html");
        template
            .replace("{{FILE_NAME}}", &clip_details.file_name)
            .replace("{{USERNAME}}", &clip_details.username)
            .replace("{{UPLOAD_DATE}}", &formatted_date)
            .replace("{{CLIP_URL}}", &clip_url)
            .replace("{{RAW_URL}}", &raw_url)
            .replace("{{AVATAR_URL}}", &uploader_avatar)
    } else {
        log!([DEBUG] => "Regular user detected, serving video player page.");
        let template = include_str!("../assets/view.html");
        template
            .replace("{{FILE_NAME}}", &clip_details.file_name)
            .replace("{{RAW_URL}}", &raw_url)
            .replace("{{AVATAR_URL}}", &uploader_avatar)
            .replace("{{USERNAME}}", &clip_details.username)
            .replace("{{UPLOAD_DATE}}", &formatted_date)
            .replace("{{REPORT_URL}}", &report_url)
    };

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html_body)
}

async fn fetch_bytes_from_storage(
    id: Uuid,
    data: &web::Data<AppState>,
) -> Result<Vec<u8>, HttpResponse> {
    log!([DEBUG] => "FETCH_FN_ENTRY: Fetching raw clip file for ID: {}", id);

    log!([DEBUG] => "PRE_DB_FETCH: Querying database for clip metadata for ID: {}", id);
    let clip: Clip = match sqlx::query_as("SELECT * FROM clips WHERE id = $1")
        .bind(id)
        .fetch_one(&data.db_pool)
        .await
    {
        Ok(c) => c,
        Err(_) => return Err(HttpResponse::NotFound().finish()),
    };
    log!([DEBUG] => "POST_DB_FETCH: Successfully found clip metadata for ID: {}", id);

    log!([DEBUG] => "PRE_STORAGE_DOWNLOAD: Calling storage.download() for clip ID: {}", id);
    let file_bytes = match data.storage.download(&clip.public_url).await {
        Ok(bytes) => {
            log!([DEBUG] => "Successfully read {} bytes from storage for clip ID {}", bytes.len(), id);
            bytes
        }
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to download file from storage for clip ID {}: {:?}", id, e);
            return Err(
                HttpResponse::InternalServerError().body("Failed to retrieve clip from storage.")
            );
        }
    };

    Ok(file_bytes)
}

#[get("/clip/{id}/raw")]
pub async fn serve_clip_raw(id: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let clip_id = *id;
    log!([DEBUG] => "HANDLER_ENTRY: /clip/{}/raw", clip_id);
    let cache_key = format!("clip_raw:{}", clip_id);

    let mut redis_conn = match data.redis_pool.get().await {
        Ok(conn) => {
            log!([DEBUG] => "Successfully acquired Redis connection for clip {}", clip_id);
            Some(conn)
        }
        Err(e) => {
            log!([DEBUG] => "ERROR: Could not get Redis connection: {:?}. Serving from storage.", e);
            None
        }
    };

    if let Some(conn) = redis_conn.as_mut() {
        log!([DEBUG] => "CACHE: Checking for key '{}'", cache_key);
        match conn.get::<_, Vec<u8>>(&cache_key).await {
            Ok(cached_data) if !cached_data.is_empty() => {
                log!([DEBUG] => "CACHE HIT: Serving clip {} from Redis.", clip_id);
                return HttpResponse::Ok()
                    .content_type("video/mp4")
                    .body(cached_data);
            }
            Ok(_) => log!([DEBUG] => "CACHE MISS: Clip {} not in Redis.", clip_id),
            Err(e) => {
                log!([DEBUG] => "ERROR: Redis GET failed for '{}': {:?}. Serving from storage.", cache_key, e)
            }
        }
    }

    log!([DEBUG] => "PRE_FETCH: About to call fetch_bytes_from_storage for clip {}", clip_id);
    let file_bytes = match fetch_bytes_from_storage(clip_id, &data).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    log!([DEBUG] => "POST_FETCH: Successfully retrieved bytes for clip {}", clip_id);

    if let Some(conn) = redis_conn.as_mut() {
        log!([DEBUG] => "CACHE SET: Caching {} bytes for clip {}.", file_bytes.len(), clip_id);
        let result: redis::RedisResult<()> = conn
            .set_ex(&cache_key, &file_bytes, CACHE_TTL_SECONDS)
            .await;
        if let Err(e) = result {
            log!([DEBUG] => "ERROR: Redis SETEX failed for key '{}': {:?}", cache_key, e);
        }
    }

    HttpResponse::Ok()
        .content_type("video/mp4")
        .body(file_bytes)
}

#[post("/clip/{id}/report")]
pub async fn report_clip(
    req: HttpRequest,
    id: web::Path<Uuid>,
    data: web::Data<AppState>,
    settings: web::Data<Settings>,
) -> impl Responder {
    log!([DEBUG] => "Received report for clip ID: {}", *id);
    let report_data = sqlx::query!(
        r#"
        SELECT c.id as clip_id, c.file_name, u.id as user_id, u.username
        FROM clips c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = $1
        "#,
        *id
    )
    .fetch_one(&data.db_pool)
    .await;

    if let Ok(report) = report_data {
        if let Some(url) = &settings.discord_webhook_url {
            let clip_url = format!("{}/clip/{}", settings.public_url, report.clip_id);
            let reporter_ip = req
                .connection_info()
                .realip_remote_addr()
                .unwrap_or("unknown")
                .to_string();
            log!([DEBUG] => "Sending Discord report notification for clip {} from IP {}", report.clip_id, reporter_ip);

            let message = serde_json::json!({
                "content": "🚨 New Clip Report! <@564472732071493633>",
                "embeds": [{
                    "title": "Reported Clip Details",
                    "color": 15158332,
                    "fields": [
                        { "name": "Clip URL", "value": clip_url, "inline": false },
                        { "name": "Uploader", "value": format!("{} (`{}`)", report.username, report.user_id), "inline": true },
                        { "name": "Reporter IP", "value": reporter_ip, "inline": true },
                    ]
                }]
            });

            let client = reqwest::Client::new();
            if let Err(e) = client.post(url).json(&message).send().await {
                log!([DEBUG] => "ERROR: Failed to send Discord notification: {}", e);
            }
        }
    }

    let html_content = include_str!("../assets/report.html");
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(html_content)
}

#[get("/clips/index")]
pub async fn get_clips_index(req: HttpRequest) -> impl Responder {
    if let Some(user_id) = req.extensions().get::<Uuid>() {
        log!([DEBUG] => "Fetching clip index for user ID: {}", user_id);
        let data: &web::Data<AppState> = req.app_data().unwrap();
        match sqlx::query_as::<_, HostedClipInfo>(
            "SELECT id, file_name FROM clips WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&data.db_pool)
        .await
        {
            Ok(clips) => {
                log!([DEBUG] => "Found {} clips for user.", clips.len());
                HttpResponse::Ok().json(clips)
            }
            Err(e) => {
                log!([DEBUG] => "ERROR: Could not fetch clips index: {}", e);
                HttpResponse::InternalServerError().body("Could not fetch clips index")
            }
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[delete("/clip/{id}")]
pub async fn delete_clip(
    req: HttpRequest,
    id: web::Path<Uuid>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user_id = match req.extensions().get::<Uuid>() {
        Some(id) => *id,
        None => return HttpResponse::Unauthorized().finish(),
    };
    let clip_id = *id;
    log!([CLEANUP] => "Received delete request for clip {} from user {}", clip_id, user_id);

    let clip_to_delete = match sqlx::query!(
        "SELECT user_id, public_url FROM clips WHERE id = $1",
        clip_id
    )
    .fetch_optional(&data.db_pool)
    .await
    {
        Ok(Some(clip)) => clip,
        Ok(None) => return HttpResponse::NotFound().finish(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if clip_to_delete.user_id != user_id {
        log!([CLEANUP] => "User {} attempted to delete clip belonging to {}", user_id, clip_to_delete.user_id);
        return HttpResponse::Forbidden().finish();
    }

    log!([CLEANUP] => "Deleting file from storage: {}", clip_to_delete.public_url);
    if let Err(e) = data.storage.delete(&clip_to_delete.public_url).await {
        log!([CLEANUP] => "ERROR: Failed to delete file from storage: {:?}", e);
    }

    log!([CLEANUP] => "Deleting clip {} from database.", clip_id);
    let db_result = sqlx::query!(
        "DELETE FROM clips WHERE id = $1 AND user_id = $2",
        clip_id,
        user_id
    )
    .execute(&data.db_pool)
    .await;

    match db_result {
        Ok(result) if result.rows_affected() > 0 => {
            log!([CLEANUP] => "Successfully deleted clip {}.", clip_id);
            if let Ok(mut conn) = data.redis_pool.get().await {
                let cache_key = format!("clip_raw:{}", clip_id);
                log!([CLEANUP] => "CACHE DEL: Invalidating key '{}'", cache_key);
                let _: redis::RedisResult<()> = conn.del(cache_key).await;
            } else {
                log!([DEBUG] => "ERROR: Could not get Redis connection for cache invalidation.");
            }
            HttpResponse::NoContent().finish()
        }
        Ok(_) => {
            log!([CLEANUP] => "Clip {} not found for user {} or already deleted.", clip_id, user_id);
            HttpResponse::NotFound().finish()
        }
        Err(e) => {
            log!([CLEANUP] => "ERROR: Failed to delete clip from database: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
