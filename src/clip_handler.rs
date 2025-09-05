use crate::{settings::Settings, AppState};
use actix_multipart::Multipart;
use actix_web::{
    delete, get, http::header::ContentType, post, web, Error, HttpMessage, HttpRequest,
    HttpResponse, Responder,
};
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
    let current_usage: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(file_size), 0) FROM clips WHERE user_id = $1")
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
            .upload(&filename, file_data)
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

        let response_url = format!("{}/clip/{}", settings.public_url, new_clip.id);
        Ok(HttpResponse::Ok().json(serde_json::json!({ "url": response_url })))
    } else {
        Err(actix_web::error::ErrorBadRequest("No file uploaded."))
    }
}

#[get("/clip/{id}")]
pub async fn serve_clip(
    req: HttpRequest,
    id: web::Path<Uuid>,
    data: web::Data<AppState>,
    settings: web::Data<Settings>,
) -> impl Responder {
    log!([DEBUG] => "Serving clip page for ID: {}", *id);
    let clip: Clip = match sqlx::query_as("SELECT * FROM clips WHERE id = $1")
        .bind(*id)
        .fetch_one(&data.db_pool)
        .await
    {
        Ok(c) => c,
        Err(_) => return HttpResponse::NotFound().body("Clip not found."),
    };

    let raw_url = format!("{}/clip/{}/raw", settings.public_url, clip.id);

    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or("");
    let is_bot = ["Discordbot", "Twitterbot", "facebookexternalhit"]
        .iter()
        .any(|bot| user_agent.contains(bot));

    if is_bot {
        log!([DEBUG] => "Bot detected ('{}'), serving meta tags.", user_agent);
        let html = format!(
            r#"<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta property="og:title" content="A clip from Wayclip" />
                <meta property="og:description" content="File: {}" />
                <meta property="og:type" content="video.other" />
                <meta property="og:video" content="{}" />
                <meta property="og:video:type" content="video/mp4" />
                <meta property="og:video:width" content="1280" />
                <meta property="og:video:height" content="720" />
                <meta name="twitter:card" content="player" />
                <meta name="twitter:title" content="A clip from Wayclip" />
                <meta name="twitter:description" content="File: {}" />
                <meta name="twitter:player" content="{}" />
                <meta name="twitter:player:width" content="1280" />
                <meta name="twitter:player:height" content="720" />
            </head>
            <body>Video shared from Wayclip.</body>
            </html>"#,
            clip.file_name, raw_url, clip.file_name, raw_url
        );
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html)
    } else {
        log!([DEBUG] => "Regular user detected, serving video player page.");
        let report_url = format!("/clip/{}/report", clip.id);
        let html = format!(
            r#"<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>Wayclip - {}</title>
                <style>
                    body, html {{ margin: 0; padding: 0; height: 100%; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #161616; color: #e0e0e0; }}
                    .container {{ display: flex; flex-direction: column; height: 100%; }}
                    video {{ width: 100%; flex-grow: 1; object-fit: contain; background-color: #000; }}
                    .footer {{ background-color: #1f1f1f; padding: 12px 20px; text-align: center; border-top: 1px solid #333; }}
                    .footer form button {{ background: #3a3a3a; border: 1px solid #555; color: #fff; padding: 8px 15px; cursor: pointer; border-radius: 5px; font-size: 14px; }}
                    .footer form button:hover {{ background: #4a4a4a; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <video controls autoplay muted playsinline src="{}"></video>
                    <div class="footer">
                        <form action="{}" method="post" onsubmit="this.querySelector('button').disabled=true; this.querySelector('button').innerText='Submitting...';">
                            <button type="submit">Report Clip</button>
                        </form>
                    </div>
                </div>
            </body>
            </html>"#,
            clip.file_name, raw_url, report_url
        );
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html)
    }
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
