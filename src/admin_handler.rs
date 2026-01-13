use crate::models::{
    AdminDashboardData, FullUserDetails, ReportedClipInfo, UpdateRolePayload, UpdateTierPayload,
    UserAdminInfo,
};
use crate::AppState;
use actix_web::{delete, get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use serde_json::json;
use sqlx::types::chrono::Utc;
use uuid::Uuid;
use wayclip_core::log;
use wayclip_core::models::HostedClipInfo;

async fn validate_and_use_token(
    token: Uuid,
    db_pool: &sqlx::PgPool,
) -> Result<(Uuid, Uuid), HttpResponse> {
    let result = sqlx::query!(
        "SELECT clip_id, user_id FROM report_tokens WHERE token = $1 AND expires_at > NOW() AND used_at IS NULL",
        token
    )
    .fetch_optional(db_pool)
    .await
    .map_err(|_| HttpResponse::InternalServerError().finish())?;

    if let Some(record) = result {
        sqlx::query!(
            "UPDATE report_tokens SET used_at = $1 WHERE token = $2",
            Utc::now(),
            token
        )
        .execute(db_pool)
        .await
        .map_err(|_| HttpResponse::InternalServerError().finish())?;
        Ok((record.clip_id, record.user_id))
    } else {
        Err(HttpResponse::Forbidden().body("Invalid, expired, or already used token."))
    }
}

#[get("/ignore/{token}")]
async fn ignore_report(token: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    match validate_and_use_token(*token, &data.db_pool).await {
        Ok(_) => {
            log!([DEBUG] => "Report with token {} ignored successfully.", *token);
            HttpResponse::Ok().body("Report has been ignored and the token invalidated.")
        }
        Err(response) => response,
    }
}

#[get("/ban/{token}")]
async fn ban_user_and_ip(token: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let (clip_id, user_id) = match validate_and_use_token(*token, &data.db_pool).await {
        Ok(ids) => ids,
        Err(response) => return response,
    };

    let mut tx = match data.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log!([DEBUG] => "DEBUG: Failed to begin transaction: {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    log!([DEBUG] => "Attempting to ban user {} via token for clip {}", user_id, clip_id);

    let user_ip: Option<String> = sqlx::query_scalar("SELECT ip_address FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or_default();

    if let Some(ip) = user_ip {
        if let Err(e) =
            sqlx::query("INSERT INTO banned_ips (ip_address) VALUES ($1) ON CONFLICT DO NOTHING")
                .bind(&ip)
                .execute(&mut *tx)
                .await
        {
            log!([DEBUG] => "DEBUG: Failed to ban IP address {}: {:?}", ip, e);
            tx.rollback().await.ok();
            return HttpResponse::InternalServerError().finish();
        }
    }

    match sqlx::query("UPDATE users SET is_banned = TRUE WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        Ok(_) => {
            if let Err(e) = tx.commit().await {
                log!([DEBUG] => "DEBUG: Failed to commit transaction: {:?}", e);
                return HttpResponse::InternalServerError().finish();
            }
            log!([DEBUG] => "Successfully banned user {}", user_id);
            HttpResponse::Ok().body(format!("User {user_id} has been banned."))
        }
        Err(e) => {
            log!([DEBUG] => "DEBUG: Failed to ban user {}: {:?}", user_id, e);
            tx.rollback().await.ok();
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/remove/{token}")]
async fn remove_video(token: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let (clip_id, user_id) = match validate_and_use_token(*token, &data.db_pool).await {
        Ok(ids) => ids,
        Err(response) => return response,
    };

    log!([DEBUG] => "Attempting to remove clip {} (from user {}) via token", clip_id, user_id);

    let clip_to_delete = match sqlx::query!("SELECT public_url FROM clips WHERE id = $1", clip_id)
        .fetch_optional(&data.db_pool)
        .await
    {
        Ok(Some(clip)) => clip,
        Ok(None) => return HttpResponse::NotFound().finish(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if let Err(e) = data.storage.delete(&clip_to_delete.public_url).await {
        log!([DEBUG] => "DEBUG: Failed to delete from storage: {:?}", e);
    }

    match sqlx::query!("DELETE FROM clips WHERE id = $1", clip_id)
        .execute(&data.db_pool)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            log!([DEBUG] => "Successfully removed clip {} from DB.", clip_id);
            HttpResponse::Ok().body(format!("Clip {clip_id} has been removed."))
        }
        Ok(_) => {
            log!([DEBUG] => "Clip {} was already removed from DB.", clip_id);
            HttpResponse::Ok().body(format!("Clip {clip_id} has been removed."))
        }
        Err(e) => {
            log!([DEBUG] => "DEBUG: Failed to delete clip from DB: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/dashboard")]
async fn get_admin_dashboard(data: web::Data<AppState>) -> impl Responder {
    let users_query = sqlx::query_as!(
        UserAdminInfo,
        r#"
        SELECT
            u.id, u.username, u.email,
            u.tier,
            u.is_banned,
            u.role as "role: _",
            COALESCE(c.clip_count, 0)::BIGINT as "clip_count!",
            COALESCE(c.total_size, 0)::BIGINT as "data_used!"
        FROM users u
        LEFT JOIN (
            SELECT user_id, COUNT(*)::BIGINT as clip_count, SUM(file_size)::BIGINT as total_size
            FROM clips GROUP BY user_id
        ) c ON u.id = c.user_id
        ORDER BY u.created_at DESC
        "#
    )
    .fetch_all(&data.db_pool)
    .await;

    let reported_clips_query = sqlx::query_as!(
        ReportedClipInfo,
        r#"
        SELECT c.id as "clip_id!", c.file_name, c.file_size, u.username as "uploader_username!", rt.token as "report_token!"
        FROM report_tokens rt
        JOIN clips c ON rt.clip_id = c.id
        JOIN users u ON c.user_id = u.id
        WHERE rt.used_at IS NULL AND rt.expires_at > NOW()
        ORDER BY rt.expires_at ASC
        "#
    )
    .fetch_all(&data.db_pool)
    .await;

    let total_usage_query: Result<Option<i64>, _> =
        sqlx::query_scalar("SELECT SUM(file_size)::BIGINT FROM clips")
            .fetch_optional(&data.db_pool)
            .await;

    match (users_query, reported_clips_query, total_usage_query) {
        (Ok(users), Ok(reported_clips), Ok(total_usage)) => {
            HttpResponse::Ok().json(AdminDashboardData {
                users,
                reported_clips,
                total_data_usage: total_usage.unwrap_or(0),
            })
        }
        _ => HttpResponse::InternalServerError().finish(),
    }
}

#[post("/users/{id}/role")]
async fn update_user_role(
    req: HttpRequest,
    path: web::Path<Uuid>,
    payload: web::Json<UpdateRolePayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let admin_id = req.extensions().get::<Uuid>().cloned().unwrap();
    let target_user_id = *path;

    if admin_id == target_user_id {
        return HttpResponse::Forbidden().body("Admins cannot change their own role.");
    }

    log!([DEBUG] => "Admin {} setting role for user {} to {:?}", admin_id, target_user_id, payload.role);

    match sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(&payload.role)
        .bind(target_user_id)
        .execute(&data.db_pool)
        .await
    {
        Ok(res) if res.rows_affected() > 0 => {
            HttpResponse::Ok().json(json!({ "message": "User role updated." }))
        }
        Ok(_) => HttpResponse::NotFound().json(json!({ "message": "User not found." })),
        Err(e) => {
            log!([DEBUG] => "Failed to update user role: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/users/{id}/tier")]
async fn update_user_tier(
    path: web::Path<Uuid>,
    payload: web::Json<UpdateTierPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let target_user_id = *path;
    log!([DEBUG] => "Admin manually setting tier for user {} to {}", target_user_id, payload.tier);

    match sqlx::query("UPDATE users SET tier = $1 WHERE id = $2")
        .bind(&payload.tier.to_lowercase())
        .bind(target_user_id)
        .execute(&data.db_pool)
        .await
    {
        Ok(res) if res.rows_affected() > 0 => {
            HttpResponse::Ok().json(json!({ "message": "User tier updated." }))
        }
        Ok(_) => HttpResponse::NotFound().json(json!({ "message": "User not found." })),
        Err(e) => {
            log!([DEBUG] => "Failed to update user tier: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/users/{id}/unban")]
async fn unban_user(path: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let user_id = *path;
    log!([DEBUG] => "Admin unbanning user {}", user_id);
    match sqlx::query("UPDATE users SET is_banned = FALSE WHERE id = $1")
        .bind(user_id)
        .execute(&data.db_pool)
        .await
    {
        Ok(res) if res.rows_affected() > 0 => {
            HttpResponse::Ok().json(json!({ "message": "User unbanned." }))
        }
        Ok(_) => HttpResponse::NotFound().json(json!({ "message": "User not found." })),
        Err(e) => {
            log!([DEBUG] => "Failed to unban user: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/users/{id}/ban")]
async fn ban_user(path: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let user_id = *path;
    log!([DEBUG] => "Admin banning user {}", user_id);
    match sqlx::query("UPDATE users SET is_banned = TRUE WHERE id = $1")
        .bind(user_id)
        .execute(&data.db_pool)
        .await
    {
        Ok(res) if res.rows_affected() > 0 => {
            HttpResponse::Ok().json(json!({ "message": "User has been banned." }))
        }
        Ok(_) => HttpResponse::NotFound().json(json!({ "message": "User not found." })),
        Err(e) => {
            log!([DEBUG] => "Failed to ban user: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[delete("/users/{id}")]
async fn delete_user(
    req: HttpRequest,
    path: web::Path<Uuid>,
    data: web::Data<AppState>,
) -> impl Responder {
    let admin_id = req.extensions().get::<Uuid>().cloned().unwrap();
    let user_id = *path;

    if admin_id == user_id {
        return HttpResponse::Forbidden().body("Admins cannot delete their own account.");
    }

    log!([DEBUG] => "Admin {} initiating permanent deletion of user {}", admin_id, user_id);

    let mut tx = match data.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let clips_to_delete: Vec<(String,)> =
        match sqlx::query_as("SELECT public_url FROM clips WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await
        {
            Ok(clips) => clips,
            Err(e) => {
                log!([DEBUG] => "Error fetching clips for deletion for user {}: {:?}", user_id, e);
                tx.rollback().await.ok();
                return HttpResponse::InternalServerError().finish();
            }
        };

    for (public_url,) in clips_to_delete {
        if let Err(e) = data.storage.delete(&public_url).await {
            log!([DEBUG] => "Failed to delete file {} from storage for user {}: {:?}", public_url, user_id, e);
        }
    }

    let queries = [
        sqlx::query("DELETE FROM clips WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await,
        sqlx::query("DELETE FROM user_credentials WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await,
        sqlx::query("DELETE FROM email_verification_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await,
        sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await,
        sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await,
        sqlx::query("DELETE FROM subscriptions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await,
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await,
    ];

    for result in queries {
        if let Err(e) = result {
            log!([DEBUG] => "Error during user {} deletion transaction: {:?}", user_id, e);
            tx.rollback().await.ok();
            return HttpResponse::InternalServerError().body("Failed to delete all user data.");
        }
    }

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError().body("Failed to commit user deletion.");
    }

    log!([DEBUG] => "Successfully deleted user {}", user_id);
    HttpResponse::Ok().json(json!({ "message": "User permanently deleted." }))
}

#[get("/users/{id}/clips")]
async fn get_user_clips(path: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let user_id = *path;
    match sqlx::query_as::<_, HostedClipInfo>(
        "SELECT id, file_name, file_size, created_at FROM clips WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&data.db_pool)
    .await
    {
        Ok(clips) => HttpResponse::Ok().json(clips),
        Err(e) => {
            log!([DEBUG] => "Admin failed to fetch clips for user {}: {:?}", user_id, e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[delete("/clips/{id}")]
async fn delete_clip_by_admin(path: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let clip_id = *path;
    log!([DEBUG] => "Admin request to delete clip {}", clip_id);

    let clip_to_delete = match sqlx::query!("SELECT public_url FROM clips WHERE id = $1", clip_id)
        .fetch_optional(&data.db_pool)
        .await
    {
        Ok(Some(clip)) => clip,
        Ok(None) => return HttpResponse::NotFound().finish(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if let Err(e) = data.storage.delete(&clip_to_delete.public_url).await {
        log!([DEBUG] => "Admin failed to delete {} from storage: {:?}", clip_to_delete.public_url, e);
    }

    match sqlx::query!("DELETE FROM clips WHERE id = $1", clip_id)
        .execute(&data.db_pool)
        .await
    {
        Ok(res) if res.rows_affected() > 0 => {
            HttpResponse::Ok().json(json!({"message": "Clip deleted."}))
        }
        Ok(_) => HttpResponse::NotFound().finish(),
        Err(e) => {
            log!([DEBUG] => "Admin failed to delete clip {} from DB: {:?}", clip_id, e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/users/{id}")]
async fn get_user_details(path: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let user_id = *path;
    let query_result = sqlx::query_as!(
        FullUserDetails,
        r#"
        SELECT
            u.id,
            u.username,
            u.email,
            u.avatar_url,
            u.tier,
            u.role as "role: _",
            u.is_banned,
            u.created_at,
            u.deleted_at,
            u.email_verified_at,
            u.two_factor_enabled,
            s.status::TEXT as "subscription_status?",
            s.current_period_end as "current_period_end?",
            (
                SELECT COALESCE(json_agg(provider), '[]'::json)
                FROM user_credentials
                WHERE user_id = u.id
            ) as "connected_providers!"
        FROM
            users u
        LEFT JOIN
            subscriptions s ON u.id = s.user_id
        WHERE
            u.id = $1
        "#,
        user_id
    )
    .fetch_one(&data.db_pool)
    .await;

    match query_result {
        Ok(details) => HttpResponse::Ok().json(details),
        Err(sqlx::Error::RowNotFound) => HttpResponse::NotFound().finish(),
        Err(e) => {
            log!([DEBUG] => "Failed to fetch full user details for user {}: {:?}", user_id, e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
