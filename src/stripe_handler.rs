use crate::AppState;
use crate::HashMap;
use actix_web::{delete, get, post, web, HttpRequest, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use stripe::{
    BillingPortalSession, CheckoutSession, Client, CreateBillingPortalSession,
    CreateCheckoutSession, CreateCheckoutSessionLineItems, CreateCheckoutSessionPaymentMethodTypes,
    EventObject, EventType, Expandable, Subscription as StripeSubscription, SubscriptionId,
    Webhook,
};
use uuid::Uuid;
use wayclip_core::log;
use wayclip_core::models::{Subscription, SubscriptionStatus, SubscriptionTier, User};

fn tier_from_price_id(price_id: &str) -> Option<SubscriptionTier> {
    let basic_id = std::env::var("STRIPE_PRICE_ID_BASIC").expect("Missing STRIPE_PRICE_ID_BASIC");
    let plus_id = std::env::var("STRIPE_PRICE_ID_PLUS").expect("Missing STRIPE_PRICE_ID_PLUS");
    let pro_id = std::env::var("STRIPE_PRICE_ID_PRO").expect("Missing STRIPE_PRICE_ID_PRO");

    match price_id {
        p if p == basic_id => Some(SubscriptionTier::Tier1),
        p if p == plus_id => Some(SubscriptionTier::Tier2),
        p if p == pro_id => Some(SubscriptionTier::Tier3),
        _ => None,
    }
}

#[post("/checkout/{tier}")]
pub async fn create_checkout_session(
    stripe_client: web::Data<Client>,
    state: web::Data<AppState>,
    user_id: web::ReqData<Uuid>,
    tier: web::Path<String>,
) -> impl Responder {
    let tier_str = tier.into_inner();
    let user_id_val = user_id.into_inner();

    let price_id = match tier_str.as_str() {
        "basic" => std::env::var("STRIPE_PRICE_ID_BASIC").ok(),
        "plus" => std::env::var("STRIPE_PRICE_ID_PLUS").ok(),
        "pro" => std::env::var("STRIPE_PRICE_ID_PRO").ok(),
        _ => None,
    };

    let price_id = match price_id {
        Some(id) => id,
        None => {
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

    let user_id = &user.id.to_string();

    let mut session_params = CreateCheckoutSession {
        success_url: Some(
            "https://dash.wayclip.com/payment/verify?session_id={CHECKOUT_SESSION_ID}",
        ),
        cancel_url: Some("https://dash.wayclip.com/payment/cancel"),
        client_reference_id: Some(user_id),
        payment_method_types: Some(vec![CreateCheckoutSessionPaymentMethodTypes::Card]),
        mode: Some(stripe::CheckoutSessionMode::Subscription),
        line_items: Some(vec![CreateCheckoutSessionLineItems {
            price: Some(price_id),
            quantity: Some(1),
            ..Default::default()
        }]),
        ..Default::default()
    };

    if let Some(stripe_customer_id) = &user.stripe_customer_id {
        if let Ok(id) = stripe_customer_id.parse() {
            session_params.customer = Some(id);
        }
    } else {
        session_params.customer_email = user.email.as_deref();
    }

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

#[post("/customer-portal")]
pub async fn create_customer_portal_session(
    stripe_client: web::Data<Client>,
    state: web::Data<AppState>,
    user_id: web::ReqData<Uuid>,
) -> impl Responder {
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id.into_inner())
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(user) => user,
        Err(_) => return HttpResponse::NotFound().json("User not found"),
    };

    let customer_id = match user.stripe_customer_id {
        Some(id) => match id.parse() {
            Ok(parsed_id) => parsed_id,
            Err(_) => return HttpResponse::BadRequest().json("Invalid Stripe customer ID format."),
        },
        None => return HttpResponse::BadRequest().json("User does not have a Stripe customer ID."),
    };

    let mut params = CreateBillingPortalSession::new(customer_id);
    params.return_url = Some("https://dash.wayclip.com/settings/billing");

    match BillingPortalSession::create(&stripe_client, params).await {
        Ok(session) => HttpResponse::Ok().json(serde_json::json!({ "url": session.url })),
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to create customer portal session: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to create customer portal session")
        }
    }
}

#[delete("/subscription")]
pub async fn cancel_subscription(
    stripe_client: web::Data<Client>,
    state: web::Data<AppState>,
    user_id: web::ReqData<Uuid>,
) -> impl Responder {
    let subscription = match sqlx::query_as::<_, Subscription>(
        "SELECT * FROM subscriptions WHERE user_id = $1 AND status = 'active'",
    )
    .bind(user_id.into_inner())
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(sub)) => sub,
        Ok(None) => return HttpResponse::NotFound().json("Active subscription not found."),
        Err(e) => {
            log!([DEBUG] => "ERROR: DB error fetching subscription: {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let sub_id: SubscriptionId = match subscription.stripe_subscription_id.parse() {
        Ok(id) => id,
        Err(_) => {
            log!([DEBUG] => "ERROR: Could not parse subscription ID from DB: {}", subscription.stripe_subscription_id);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let params = stripe::UpdateSubscription {
        cancel_at_period_end: Some(true),
        ..Default::default()
    };

    match StripeSubscription::update(&stripe_client, &sub_id, params).await {
        Ok(_) => {
            log!([DEBUG] => "Subscription {} marked for cancellation at period end.", sub_id);
            HttpResponse::Ok()
                .json(serde_json::json!({"message": "Subscription cancellation scheduled."}))
        }
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to cancel Stripe subscription {}: {:?}", sub_id, e);
            HttpResponse::InternalServerError().json("Failed to cancel subscription")
        }
    }
}

#[post("/stripe-webhook")]
pub async fn stripe_webhook(
    req: HttpRequest,
    payload: web::Bytes,
    state: web::Data<AppState>,
    stripe_client: web::Data<Client>,
) -> impl Responder {
    let signature = match req.headers().get("Stripe-Signature") {
        Some(s) => s.to_str().unwrap_or(""),
        None => return HttpResponse::BadRequest().finish(),
    };

    let webhook_secret =
        std::env::var("STRIPE_WEBHOOK_SECRET").expect("Missing STRIPE_WEBHOOK_SECRET");

    let event = match Webhook::construct_event(
        std::str::from_utf8(&payload).unwrap(),
        signature,
        &webhook_secret,
    ) {
        Ok(e) => e,
        Err(e) => {
            log!([DEBUG] => "ERROR: Webhook signature verification failed: {:?}", e);
            return HttpResponse::BadRequest().body(e.to_string());
        }
    };

    match event.type_ {
        EventType::CheckoutSessionCompleted => {
            if let EventObject::CheckoutSession(session) = event.data.object {
                handle_checkout_session_completed(&state, &stripe_client, session).await;
            }
        }
        EventType::CustomerSubscriptionUpdated => {
            if let EventObject::Subscription(sub) = event.data.object {
                handle_subscription_updated(&state, sub).await;
            }
        }
        EventType::CustomerSubscriptionDeleted => {
            if let EventObject::Subscription(sub) = event.data.object {
                handle_subscription_deleted(&state, sub).await;
            }
        }
        _ => {
            log!([DEBUG] => "Received unhandled Stripe event type: {:?}", event.type_);
        }
    }

    HttpResponse::Ok().finish()
}

async fn handle_checkout_session_completed(
    state: &web::Data<AppState>,
    stripe_client: &Client,
    session: CheckoutSession,
) {
    let user_id: Uuid = match session.client_reference_id.as_ref().and_then(|id| id.parse().ok()) {
        Some(id) => id,
        None => {
            log!([DEBUG] => "ERROR: Failed to parse UUID from client_reference_id or it was missing");
            return;
        }
    };

    let stripe_sub_id = match session.subscription {
        Some(Expandable::Id(id)) => id,
        _ => {
            log!([DEBUG] => "ERROR: Subscription ID missing from checkout session for user {}", user_id);
            return;
        }
    };

    let subscription = match StripeSubscription::retrieve(stripe_client, &stripe_sub_id, &[]).await
    {
        Ok(sub) => sub,
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to retrieve subscription {}: {:?}", stripe_sub_id, e);
            return;
        }
    };

    let stripe_customer_id = match &subscription.customer {
        Expandable::Id(id) => id.to_string(),
        Expandable::Object(customer) => customer.id.to_string(),
    };

    let price_id = match subscription.items.data.first().and_then(|item| item.price.as_ref()) {
        Some(price) => price.id.to_string(),
        None => {
            log!([DEBUG] => "ERROR: Price object missing from subscription item for sub {}", stripe_sub_id);
            return;
        }
    };

    let tier = tier_from_price_id(&price_id).unwrap_or(SubscriptionTier::Free);

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to begin database transaction: {:?}", e);
            return;
        }
    };

    if let Err(e) = sqlx::query("UPDATE users SET tier = $1, stripe_customer_id = $2 WHERE id = $3")
        .bind(tier as SubscriptionTier)
        .bind(&stripe_customer_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        log!([DEBUG] => "ERROR: Failed to update user on checkout completion: {:?}", e);
        tx.rollback().await.ok();
        return;
    }
    
    let (start_date, end_date) = (
        DateTime::from_timestamp(subscription.current_period_start, 0),
        DateTime::from_timestamp(subscription.current_period_end, 0)
    );

    if start_date.is_none() || end_date.is_none() {
        log!([DEBUG] => "ERROR: Invalid timestamp from Stripe for sub {}", stripe_sub_id);
        tx.rollback().await.ok();
        return;
    }

    let status: SubscriptionStatus = subscription.status.to_string().parse().unwrap_or(SubscriptionStatus::Incomplete);
    let query_result = sqlx::query!(
        r#"
        INSERT INTO subscriptions (user_id, stripe_subscription_id, stripe_price_id, status, current_period_start, current_period_end)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id) DO UPDATE
        SET stripe_subscription_id = EXCLUDED.stripe_subscription_id,
            stripe_price_id = EXCLUDED.stripe_price_id,
            status = EXCLUDED.status,
            current_period_start = EXCLUDED.current_period_start,
            current_period_end = EXCLUDED.current_period_end,
            cancel_at_period_end = false,
            canceled_at = NULL,
            updated_at = NOW()
        "#,
        user_id,
        subscription.id.to_string(),
        price_id,
        status as SubscriptionStatus,
        start_date.unwrap(),
        end_date.unwrap()
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = query_result {
        log!([DEBUG] => "ERROR: Failed to insert/update subscription: {:?}", e);
        tx.rollback().await.ok();
        return;
    }

    if let Err(e) = tx.commit().await {
        log!([DEBUG] => "ERROR: Failed to commit transaction for user {}: {:?}", user_id, e);
        return;
    }
    log!([DEBUG] => "Successfully processed checkout for user {}", user_id);
}

async fn handle_subscription_updated(state: &web::Data<AppState>, sub: StripeSubscription) {
    let stripe_sub_id = sub.id.to_string();
    let status: SubscriptionStatus = sub.status.to_string().parse().unwrap_or(SubscriptionStatus::Incomplete);

    let price_id = match sub.items.data.first().and_then(|item| item.price.as_ref()) {
        Some(price) => price.id.to_string(),
        None => {
            log!([DEBUG] => "ERROR: Price object missing from updated subscription item for sub {}", stripe_sub_id);
            return;
        }
    };

    let tier = tier_from_price_id(&price_id).unwrap_or(SubscriptionTier::Free);

    let (start_date, end_date) = (
        DateTime::from_timestamp(sub.current_period_start, 0),
        DateTime::from_timestamp(sub.current_period_end, 0),
    );

    if start_date.is_none() || end_date.is_none() {
        log!([DEBUG] => "ERROR: Invalid timestamp from Stripe for updated sub {}", stripe_sub_id);
        return;
    }

    let query_result = sqlx::query!(
        r#"
        UPDATE subscriptions
        SET status = $1,
            stripe_price_id = $2,
            current_period_start = $3,
            current_period_end = $4,
            cancel_at_period_end = $5,
            updated_at = NOW()
        WHERE stripe_subscription_id = $6
        RETURNING user_id
        "#,
        status as SubscriptionStatus,
        price_id,
        start_date.unwrap(),
        end_date.unwrap(),
        sub.cancel_at_period_end,
        stripe_sub_id,
    )
    .fetch_one(&state.db_pool)
    .await;

    let user_id = match query_result {
        Ok(rec) => rec.user_id,
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to update subscription {}: {:?}", stripe_sub_id, e);
            return;
        }
    };

    let final_tier = if status == SubscriptionStatus::Active {
        tier
    } else {
        SubscriptionTier::Free
    };

    if let Err(e) = sqlx::query!(
        "UPDATE users SET tier = $1 WHERE id = $2",
        final_tier as SubscriptionTier,
        user_id
    )
    .execute(&state.db_pool)
    .await
    {
        log!([DEBUG] => "ERROR: Failed to update user tier for sub {}: {:?}", stripe_sub_id, e);
    } else {
        log!([DEBUG] => "Successfully updated subscription {} and user {}", stripe_sub_id, user_id);
    }
}

async fn handle_subscription_deleted(state: &web::Data<AppState>, sub: StripeSubscription) {
    let stripe_sub_id = sub.id.to_string();
    let canceled_at: Option<DateTime<Utc>> = sub.canceled_at.and_then(|ts| DateTime::from_timestamp(ts, 0));

    let query_result = sqlx::query!(
        r#"
        UPDATE subscriptions
        SET status = 'canceled',
            canceled_at = $1,
            updated_at = NOW()
        WHERE stripe_subscription_id = $2
        RETURNING user_id
        "#,
        canceled_at,
        stripe_sub_id,
    )
    .fetch_one(&state.db_pool)
    .await;

    let user_id = match query_result {
        Ok(rec) => rec.user_id,
        Err(e) => {
            log!([DEBUG] => "ERROR: Failed to update subscription on deletion {}: {:?}", stripe_sub_id, e);
            return;
        }
    };

    if let Err(e) = sqlx::query!("UPDATE users SET tier = 'free' WHERE id = $1", user_id)
        .execute(&state.db_pool)
        .await
    {
        log!([DEBUG] => "ERROR: Failed to downgrade user tier for sub {}: {:?}", stripe_sub_id, e);
    } else {
        log!([DEBUG] => "Successfully processed subscription deletion {} for user {}", stripe_sub_id, user_id);
    }
}

#[get("/checkout/verify-session")]
pub async fn verify_checkout_session(
    stripe_client: web::Data<Client>,
    state: web::Data<AppState>,
    user_id: web::ReqData<Uuid>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let session_id = match query.get("session_id") {
        Some(id) => id,
        None => return HttpResponse::BadRequest().json("Missing session_id"),
    };

    let session_id_parsed = match session_id.parse() {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json("Invalid session_id"),
    };

    let session = match CheckoutSession::retrieve(&stripe_client, &session_id_parsed, &[])
        .await
    {
        Ok(s) => s,
        Err(_) => return HttpResponse::InternalServerError().json("Failed to retrieve session"),
    };

    if let Some(client_ref_id) = &session.client_reference_id {
        if *client_ref_id != user_id.into_inner().to_string() {
            return HttpResponse::Forbidden()
                .json("Session does not belong to the authenticated user");
        }
    }

    if session.payment_status == stripe::CheckoutSessionPaymentStatus::Paid {
        log!([DEBUG] => "Verifying paid session {}. Running completion handler as a fallback.", session_id);
        handle_checkout_session_completed(&state, &stripe_client, session.clone()).await;

        HttpResponse::Ok().json(serde_json::json!({ "status": "paid" }))
    } else {
        HttpResponse::Ok().json(serde_json::json!({ "status": session.status }))
    }
}
