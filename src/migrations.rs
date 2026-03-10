use sqlx::{
    Pool, Sqlite,
    migrate::{MigrateError, Migrator},
};
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Runs migration files of this module.
/// Use this method if and only if this is the only sqlx migration you are running on your app.
/// This is because sqlx will fail all successive migrations if they are like this one.
/// If you have multiple migrations, copy all the migration files into one place and run them once using sql::Migrator::run.
/// You can find the migration files of this module at ./migrations directory
pub async fn run_migration(pool: &Pool<Sqlite>) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}
