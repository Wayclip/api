use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use wayclip_core::log;

pub async fn create_pool(database_url: &str) -> Result<Pool<Postgres>, sqlx::Error> {
    log!([DEBUG] => "Attempting to create PostgreSQL connection pool...");
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}
