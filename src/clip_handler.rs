use crate::AppState;
use actix_multipart::Multipart;
use actix_web::http::header::{self, ContentType};
use actix_web::{delete, get, post, web, Error, HttpMessage, HttpRequest, HttpResponse, Responder};
use chrono::{DateTime, Duration, Utc};
use futures_util::stream::StreamExt;
use http_range::HttpRange;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;
use wayclip_core::log;
use wayclip_core::models::{Clip, HostedClipInfo, User};

#[derive(serde::Deserialize)]
pub struct ShareBeginRequest {
    file_name: String,
    file_size: i64,
}

#[post("/begin")]
pub async fn share_clip_begin(
    req: HttpRequest,
    body: web::Json<ShareBeginRequest>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let settings = data.settings.clone();
    log!([DEBUG] => "Received clip share/begin request.");
    let max_file_size = settings.upload_limit_bytes.unwrap_or(1024 * 1024 * 1024) as i64; // 1GiB

    let user_id = req
        .extensions()
        .get::<Uuid>()
        .cloned()
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Not authenticated"))?;

    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&data.db_pool)
        .await
        .map_err(|_| actix_web::error::ErrorNotFound("User not found"))?;

    if user.is_banned {
        return Err(actix_web::error::ErrorForbidden(
            "This account is suspended.",
        ));
    }

    let sanitized_file_name = body.file_name.trim();
    if sanitized_file_name.is_empty() || sanitized_file_name.len() > 255 {
        return Err(actix_web::error::ErrorBadRequest("Invalid file name."));
    }

    let tier_info = data.tiers.get(&user.tier.to_lowercase());

    if tier_info.is_none() {
        log!([DEBUG] => "WARNING: User {} has unknown tier '{}'. Map keys: {:?}", 
        user.id, user.tier, data.tiers.keys());
    }

    let tier_limit = tier_info.map(|t| t.max_storage_bytes).unwrap_or(0);

    let current_usage: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(file_size), 0)::BIGINT FROM clips WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&data.db_pool)
    .await
    .unwrap_or(0);

    if body.file_size > max_file_size {
        return Err(actix_web::error::ErrorPayloadTooLarge(format!(
            "File size cannot exceed {max_file_size} bytes",
        )));
    }
    if current_usage + body.file_size > tier_limit {
        return Err(actix_web::error::ErrorForbidden(
            "Storage limit exceeded for your subscription tier.",
        ));
    }

    let new_clip: Clip = sqlx::query_as(
        "INSERT INTO clips (user_id, file_name, file_size, public_url, status) VALUES ($1, $2, $3, $4, 'pending') RETURNING *",
    )
    .bind(user_id)
    .bind(sanitized_file_name)
    .bind(body.file_size)
    .bind(format!("{}.mp4", Uuid::new_v4()))
    .fetch_one(&data.db_pool)
    .await
    .map_err(|e| {
        log!([DEBUG] => "ERROR: DB insert for pending clip failed: {:?}", e);
        actix_web::error::ErrorInternalServerError("Failed to initiate clip upload.")
    })?;

    let response_url = format!("{}/clip/{}", settings.backend_url, new_clip.id);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "upload_id": new_clip.id,
        "url": response_url
    })))
}

#[post("/upload/{upload_id}")]
pub async fn share_clip_upload(
    mut payload: Multipart,
    upload_id: web::Path<Uuid>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let clip_id = *upload_id;
    log!([DEBUG] => "Received file stream for upload ID: {}", clip_id);

    let clip: Clip = sqlx::query_as("SELECT * FROM clips WHERE id = $1 AND status = 'pending'")
        .bind(clip_id)
        .fetch_one(&data.db_pool)
        .await
        .map_err(|e| {
            log!([DEBUG] => "Failed to find pending clip for upload: {}. Error: {:?}", clip_id, e);
            actix_web::error::ErrorNotFound("Upload ID not found or already completed")
        })?;

    if let Some(field_result) = payload.next().await {
        let mut field = field_result?;
        let (tx, rx) = mpsc::channel(4);
        let background_data = data.clone();

        actix_web::rt::spawn(async move {
            log!([DEBUG] => "[BG] Starting background storage upload for clip ID: {}", clip_id);
            let stream = ReceiverStream::new(rx);

            if let Err(e) = background_data
                .storage
                .upload(&clip.public_url, Box::new(stream))
                .await
            {
                log!([DEBUG] => "ERROR: [BG] Storage upload failed for clip {}: {:?}", clip_id, e);
                let _ = sqlx::query("UPDATE clips SET status = 'failed' WHERE id = $1")
                    .bind(clip_id)
                    .execute(&background_data.db_pool)
                    .await;
            } else {
                log!([DEBUG] => "[BG] Storage upload successful for clip {}", clip_id);
                let _ = sqlx::query("UPDATE clips SET status = 'completed' WHERE id = $1")
                    .bind(clip_id)
                    .execute(&background_data.db_pool)
                    .await;
            }
        });

        while let Some(chunk_result) = field.next().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    log!([DEBUG] => "Multipart stream chunk error for clip ID {}: {:?}", clip_id, e);
                    let io_err = std::io::Error::other(e.to_string());
                    let _ = tx.send(Err(io_err)).await;
                    break;
                }
            };

            if tx.send(Ok(chunk)).await.is_err() {
                log!([DEBUG] => "Upload channel closed prematurely for clip ID: {}. Aborting.", clip_id);
                break;
            }
        }

        Ok(HttpResponse::Ok().finish())
    } else {
        Err(actix_web::error::ErrorBadRequest("No file in upload body."))
    }
}

fn sanitize_display_name(name: &str) -> String {
    let mut display_name = name.trim().to_string();
    if display_name.ends_with(".mp4") {
        display_name = display_name[..display_name.len() - 4].to_string();
    }
    display_name.replace('_', " ")
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
) -> impl Responder {
    let settings = data.settings.clone();
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
            log!([DEBUG] => "Clip with ID {} not found.", *id);
            let template = include_str!("../assets/not_found.html");
            return HttpResponse::NotFound()
                .content_type("text/html; charset=utf-8")
                .body(template);
        }
    };

    let display_name = sanitize_display_name(&clip_details.file_name);
    let escaped_file_name = html_escape::encode_text(&display_name);
    let escaped_username = html_escape::encode_text(&clip_details.username);

    let clip_url = format!("{}/clip/{}", settings.backend_url, clip_details.id);
    let raw_url = format!("{}/clip/{}/raw", settings.backend_url, clip_details.id);
    let report_url = format!("/clip/{}/report", clip_details.id);
    let uploader_avatar = clip_details.avatar_url.clone().unwrap_or_else(|| {
        settings
            .default_avatar_url
            .clone()
            .unwrap_or_else(|| "https://avatars.githubusercontent.com/u/1024025?v=4".to_string())
    });
    let formatted_date = clip_details.created_at.format("%B %e, %Y").to_string();
    let iso_date = clip_details.created_at.to_rfc3339();

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
            .replace("{{FILE_NAME}}", &escaped_file_name)
            .replace("{{USERNAME}}", &escaped_username)
            .replace("{{UPLOAD_DATE}}", &formatted_date)
            .replace("{{UPLOAD_DATE_ISO}}", &iso_date)
            .replace("{{CLIP_URL}}", &clip_url)
            .replace("{{RAW_URL}}", &raw_url)
            .replace("{{AVATAR_URL}}", &uploader_avatar)
            .replace("{{UUID}}", &clip_details.id.to_string())
    } else {
        log!([DEBUG] => "Regular user detected, serving video player page.");
        let template = include_str!("../assets/view.html");
        template
            .replace("{{FILE_NAME}}", &escaped_file_name)
            .replace("{{RAW_URL}}", &raw_url)
            .replace("{{AVATAR_URL}}", &uploader_avatar)
            .replace("{{USERNAME}}", &escaped_username)
            .replace("{{UPLOAD_DATE}}", &formatted_date)
            .replace("{{REPORT_URL}}", &report_url)
    };

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html_body)
}

#[get("/clip/{id}/raw")]
pub async fn serve_clip_raw(
    req: HttpRequest,
    id: web::Path<Uuid>,
    data: web::Data<AppState>,
) -> impl Responder {
    let clip_id = *id;
    let range_header = req
        .headers()
        .get(header::RANGE)
        .and_then(|h| h.to_str().ok());

    log!([DEBUG] => "Streaming clip {} from storage.", clip_id);

    let clip: Clip = match sqlx::query_as("SELECT * FROM clips WHERE id = $1")
        .bind(clip_id)
        .fetch_one(&data.db_pool)
        .await
    {
        Ok(c) => c,
        Err(_) => return HttpResponse::NotFound().finish(),
    };

    let range_tuple = match range_header {
        Some(range_str) => match HttpRange::parse(range_str, clip.file_size as u64) {
            Ok(ranges) if !ranges.is_empty() => {
                let r = ranges[0];
                Some((r.start, r.length))
            }
            _ => return HttpResponse::RangeNotSatisfiable().finish(),
        },
        None => None,
    };

    match data
        .storage
        .download_stream(&clip.public_url, range_tuple)
        .await
    {
        Ok(stream_response) => {
            let mut builder = if range_header.is_some() {
                HttpResponse::PartialContent()
            } else {
                HttpResponse::Ok()
            };

            builder
                .content_type("video/mp4")
                .insert_header((header::ACCEPT_RANGES, "bytes"))
                .insert_header((header::CONTENT_LENGTH, stream_response.content_length))
                .insert_header((header::CONTENT_RANGE, stream_response.content_range));

            builder.streaming(stream_response.stream)
        }
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to create download stream for clip {}: {:?}", clip_id, e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/clip/{id}/report")]
pub async fn report_clip(
    req: HttpRequest,
    id: web::Path<Uuid>,
    data: web::Data<AppState>,
) -> impl Responder {
    let settings = data.settings.clone();
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
        let new_token = Uuid::new_v4();
        let expiration_time = Utc::now() + Duration::hours(24);

        let db_result = sqlx::query!(
        "INSERT INTO report_tokens (token, clip_id, user_id, expires_at) VALUES ($1, $2, $3, $4)",
        new_token,
        report.clip_id,
        report.user_id,
        expiration_time
    )
        .execute(&data.db_pool)
        .await;

        if let Err(e) = db_result {
            log!([DEBUG] => "ERROR: Failed to create report token: {}", e);
            return HttpResponse::InternalServerError().finish();
        }

        if settings.discord_notifications.unwrap_or(false) {
            if let Some(url) = &settings.discord_webhook_url {
                if let Some(user_id) = &settings.discord_userid {
                    let display_name = sanitize_display_name(&report.file_name);
                    let clip_url = format!("{}/clip/{}", settings.backend_url, report.clip_id);
                    let ban_url = format!("{}/admin/ban/{}", settings.backend_url, new_token);
                    let remove_url = format!("{}/admin/remove/{}", settings.backend_url, new_token);
                    let reporter_ip = req
                        .connection_info()
                        .realip_remote_addr()
                        .unwrap_or("unknown")
                        .to_string();
                    log!([DEBUG] => "Sending Discord report notification for clip {} from IP {}", report.clip_id, reporter_ip);

                    let message = serde_json::json!({
                        "content": format!("🚨 New Clip Report! <@{}>", user_id),
                        "embeds": [{
                            "title": "Reported Clip Details",
                            "color": 15158332,
                            "fields": [
                                {
                                    "name": "Uploader",
                                    "value": format!("{} (`{}`)", report.username, report.user_id),
                                    "inline": true
                                },
                                {
                                    "name": "Reporter IP",
                                    "value": reporter_ip,
                                    "inline": true
                                },
                                {
                                    "name": "File Name",
                                    "value": display_name,
                                    "inline": false
                                },
                                {
                                    "name": "Actions",
                                    "value": format!(
                                        "🔗 [View Clip]({})\n🔨 [Ban User]({})\n🗑️ [Remove Video]({})",
                                        clip_url, ban_url, remove_url
                                    )
                                }
                            ]
                        }]
                    });

                    let client = reqwest::Client::new();
                    let response = client.post(url).json(&message).send().await;

                    match response {
                        Ok(res) => {
                            if !res.status().is_success() {
                                let status = res.status();
                                let error_body = res
                                    .text()
                                    .await
                                    .unwrap_or_else(|_| "Could not read response body".to_string());
                                log!([DEBUG] => "ERROR: Discord webhook failed. Status: {}. Body: {}", status, error_body);
                            } else {
                                log!([DEBUG] => "Successfully sent Discord notification.");
                            }
                        }
                        Err(e) => {
                            log!([DEBUG] => "ERROR: Failed to send Discord notification request: {}", e);
                        }
                    }
                }
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
            "SELECT id, file_name, file_size, created_at FROM clips WHERE user_id = $1 ORDER BY created_at DESC",
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

#[get("/clip/{id}/meta")]
pub async fn serve_clip_oembed(id: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let settings = data.settings.clone();
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
        Err(_) => return HttpResponse::NotFound().finish(),
    };

    let display_name = sanitize_display_name(&clip_details.file_name);
    let raw_url = format!("{}/clip/{}/raw", settings.backend_url, clip_details.id);
    let uploader_avatar = clip_details.avatar_url.clone().unwrap_or_else(|| {
        settings
            .default_avatar_url
            .clone()
            .unwrap_or_else(|| "https://avatars.githubusercontent.com/u/1024025?v=4".to_string())
    });

    let oembed_response = serde_json::json!({
        "version": "1.0",
        "type": "video",
        "author_name": clip_details.username,
        "provider_name": settings.app_name,
        "provider_url": settings.backend_url,
        "thumbnail_url": uploader_avatar,
        "thumbnail_width": 128,
        "thumbnail_height": 128,
        "title": display_name,
        "video": {
            "url": raw_url,
            "width": 1280,
            "height": 720
        }
    });

    HttpResponse::Ok().json(oembed_response)
}

#[get("/get-app-info")]
pub async fn get_app_info(state: web::Data<AppState>) -> impl Responder {
    let settings = state.settings.clone();
    HttpResponse::Ok().json(json!({
        "backend_url": settings.backend_url,
        "frontend_url": settings.frontend_url,
        "app_name": settings.app_name,
        "default_avatar_url": settings.default_avatar_url,
        "upload_limit_bytes": settings.upload_limit_bytes
    }))
}
