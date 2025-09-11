use crate::AppState;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use redis::AsyncCommands;
use stripe::{
    CheckoutSession, Client, CreateCheckoutSession, CreateCheckoutSessionLineItems,
    CreateCheckoutSessionLineItemsPriceData, CreateCheckoutSessionLineItemsPriceDataProductData,
    CreateCheckoutSessionPaymentMethodTypes, Currency, CustomerId, EventObject, EventType, Webhook,
};
use uuid::Uuid;
use wayclip_core::log;
use wayclip_core::models::{SubscriptionTier, User};

#[post("/checkout/{tier}")]
pub async fn create_checkout_session(
    stripe_client: web::Data<Client>,
    state: web::Data<AppState>,
    user_id: web::ReqData<Uuid>,
    tier: web::Path<String>,
) -> impl Responder {
    let tier_str = tier.into_inner();
    let user_id_val = user_id.into_inner();

    let (plan_name, unit_amount, tier_enum) = match tier_str.as_str() {
        "basic" => ("Basic Plan", 299, SubscriptionTier::Tier1),
        "plus" => ("Plus Plan", 699, SubscriptionTier::Tier2),
        "pro" => ("Pro Plan", 1499, SubscriptionTier::Tier3),
        _ => {
            log!([DEBUG] => "ERROR: Invalid subscription tier provided: {}", tier_str);
            return HttpResponse::BadRequest().json("Invalid subscription tier");
        }
    };

    log!([DEBUG] => "Creating checkout session for user {} with tier '{}'", user_id_val, tier_str);

    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id_val)
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(user) => user,
        Err(_) => return HttpResponse::NotFound().json("User not found"),
    };

    let session_params = CreateCheckoutSession {
        customer: user.stripe_customer_id.as_ref().map(|id| {
            id.parse::<CustomerId>()
                .expect("Invalid Stripe Customer ID in DB")
        }),

        customer_email: if user.stripe_customer_id.is_some() {
            None
        } else {
            Some(&user.username)
        },

        payment_method_types: Some(vec![
            CreateCheckoutSessionPaymentMethodTypes::Card,
            CreateCheckoutSessionPaymentMethodTypes::Paypal,
        ]),

        line_items: Some(vec![CreateCheckoutSessionLineItems {
            price_data: Some(CreateCheckoutSessionLineItemsPriceData {
                currency: Currency::USD,
                product_data: Some(CreateCheckoutSessionLineItemsPriceDataProductData {
                    name: plan_name.to_string(),
                    ..Default::default()
                }),
                unit_amount: Some(unit_amount),
                ..Default::default()
            }),
            quantity: Some(1),
            ..Default::default()
        }]),
        mode: Some(stripe::CheckoutSessionMode::Payment),
        success_url: Some("https://wayclip.com/payment/success?session_id={CHECKOUT_SESSION_ID}"),
        cancel_url: Some("https://wayclip.com/payment/cancel"),
        metadata: Some(
            [
                ("user_id".to_string(), user_id_val.to_string()),
                ("tier".to_string(), tier_enum.to_string()),
            ]
            .iter()
            .cloned()
            .collect(),
        ),
        ..Default::default()
    };

    let session = match CheckoutSession::create(&stripe_client, session_params).await {
        Ok(s) => s,
        Err(e) => {
            log!([DEBUG] => "ERROR: Stripe session creation failed: {:?}", e);
            return HttpResponse::InternalServerError().json("Failed to create Stripe session");
        }
    };

    match session.url {
        Some(url) => HttpResponse::Ok().json(serde_json::json!({ "url": url })),
        None => {
            log!([DEBUG] => "ERROR: Stripe session URL is missing.");
            HttpResponse::InternalServerError().json("Failed to get session URL")
        }
    }
}

#[post("/stripe-webhook")]
pub async fn stripe_webhook(
    req: HttpRequest,
    payload: web::Bytes,
    state: web::Data<AppState>,
) -> impl Responder {
    let signature = match req.headers().get("Stripe-Signature") {
        Some(s) => s.to_str().unwrap_or(""),
        None => {
            log!([DEBUG] => "ERROR: Missing Stripe-Signature header");
            return HttpResponse::BadRequest().finish();
        }
    };

    let webhook_secret =
        std::env::var("STRIPE_WEBHOOK_SECRET").expect("Missing STRIPE_WEBHOOK_SECRET");

    let payload_str = match str::from_utf8(&payload) {
        Ok(s) => s,
        Err(e) => {
            log!([DEBUG] => "ERROR: Webhook payload was not valid UTF-8: {:?}", e);
            return HttpResponse::BadRequest().body("Invalid UTF-8 sequence");
        }
    };

    let event = match Webhook::construct_event(payload_str, signature, &webhook_secret) {
        Ok(e) => e,
        Err(e) => {
            log!([DEBUG] => "ERROR: Stripe webhook signature verification failed: {:?}", e);
            return HttpResponse::BadRequest().body(e.to_string());
        }
    };

    let mut redis_conn = match state.redis_pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            log!([DEBUG] => "ERROR: Could not get Redis connection: {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let redis_key = format!("stripe_event_id:{}", event.id);
    let was_set: i32 = match redis_conn.set_nx(&redis_key, 1).await {
        Ok(val) => val,
        Err(e) => {
            log!([DEBUG] => "ERROR: Redis SETNX failed: {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    if was_set == 0 {
        log!([DEBUG] => "Duplicate event received, already processed: {}", event.id);
        return HttpResponse::Ok().body("Duplicate event");
    }

    let _: () = redis_conn
        .expire(&redis_key, 60 * 60 * 24 * 3)
        .await
        .unwrap_or_default();

    if let EventObject::CheckoutSession(session) = event.data.object {
        if event.type_ == EventType::CheckoutSessionCompleted {
            log!([DEBUG] => "CheckoutSessionCompleted event received for session: {}", session.id);

            let metadata = match session.metadata {
                Some(meta) => meta,
                None => {
                    log!([DEBUG] => "ERROR: Metadata missing from webhook for session: {}", session.id);
                    return HttpResponse::BadRequest().body("Metadata missing");
                }
            };

            let user_id_str = metadata
                .get("user_id")
                .expect("user_id missing from metadata");
            let tier_str = metadata.get("tier").expect("tier missing from metadata");
            let stripe_customer_id = session.customer.as_ref().expect("customer id missing").id();
            let user_id = Uuid::parse_str(user_id_str).expect("Failed to parse UUID");
            let tier: SubscriptionTier = tier_str.parse().expect("Invalid tier in metadata");

            log!([DEBUG] => "Updating user {} to tier {:?} with stripe_customer_id {}", user_id, tier, stripe_customer_id);

            let query_result = sqlx::query!(
                "UPDATE users SET tier = $1, stripe_customer_id = $2 WHERE id = $3",
                tier as SubscriptionTier,
                stripe_customer_id.to_string(),
                user_id
            )
            .execute(&state.db_pool)
            .await;

            match query_result {
                Ok(result) if result.rows_affected() == 1 => {
                    log!([DEBUG] => "Successfully updated user {} in database.", user_id);
                }
                Ok(_) => {
                    log!([DEBUG] => "ERROR: User {} not found for update.", user_id);
                }
                Err(e) => {
                    log!([DEBUG] => "ERROR: Failed to update user {} in database: {:?}", user_id, e);
                    return HttpResponse::InternalServerError().finish();
                }
            }
        }
    } else {
        log!([DEBUG] => "Received unhandled Stripe event type: {:?}", event.type_);
    }

    HttpResponse::Ok().finish()
}
