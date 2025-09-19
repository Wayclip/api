use crate::AppState;
use actix_web::{get, web, HttpResponse, Responder};
use chrono::Utc;
use uuid::Uuid;
use wayclip_core::log;

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

#[get("/ban/{token}")]
async fn ban_user_and_ip(token: web::Path<Uuid>, data: web::Data<AppState>) -> impl Responder {
    let (clip_id, user_id) = match validate_and_use_token(*token, &data.db_pool).await {
        Ok(ids) => ids,
        Err(response) => return response,
    };

    let mut tx = match data.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to begin transaction: {:?}", e);
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
            log!([DEBUG] => "ERROR: Failed to ban IP address {}: {:?}", ip, e);
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
                log!([DEBUG] => "ERROR: Failed to commit transaction: {:?}", e);
                return HttpResponse::InternalServerError().finish();
            }
            log!([DEBUG] => "Successfully banned user {}", user_id);
            HttpResponse::Ok().body(format!("User {user_id} has been banned."))
        }
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to ban user {}: {:?}", user_id, e);
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
        log!([DEBUG] => "ERROR: Failed to delete from storage: {:?}", e);
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
            log!([DEBUG] => "ERROR: Failed to delete clip from DB: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
