use sqlx::{
    Pool, Sqlite,
    migrate::{MigrateError, Migrator},
};
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub async fn run_migration(pool: &Pool<Sqlite>) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}
