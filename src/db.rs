use num_bigint::BigUint;
use sqlx::{PgPool, Postgres, Transaction};
use chrono::{Date, DateTime, Utc};

pub struct User {
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    pub created_at: DateTime<Utc>,
}

pub struct AuthLog {
    pub user_name: String,
    pub auth_id: String,
    pub success: bool,
    pub created_at: DateTime<Utc>,
    pub failure_reason: Option<String>,
}

pub struct Session {
    pub user_name: String,
    pub session_id: String,
    pub auth_id: String,
    pub created_at: DateTime<Utc>,
}

/// INSERT FUNCTIONS ///
pub async fn insert_user(
    tx: &mut Transaction<'_, Postgres>,
    user: User,
) -> Result<(), sqlx::Error> {
    if user.user_name.is_empty() {
        return Ok(()); // If the user vector is empty, return early.
    }
    sqlx::query!(
        "INSERT INTO users (user_name, y1, y2, created_at) VALUES ($1, $2, $3, $4)",
        user.user_name,
        user.y1.to_bytes_be(),
        user.y2.to_bytes_be(),
        user.created_at.naive_utc()
    )
    .execute(&mut **tx)
    .await?;

    Ok(())
}

pub async fn insert_login_attempt(
    tx: &mut Transaction<'_, Postgres>,
    auth_log: AuthLog,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO auth_logs (user_name, auth_id, success, created_at, failure_reason) VALUES ($1, $2, $3, $4, $5)",
        auth_log.user_name,
        auth_log.auth_id,
        auth_log.success,
        auth_log.created_at.naive_utc(),
        auth_log.failure_reason
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn insert_session(
    tx: &mut Transaction<'_, Postgres>,
    session: Session,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO sessions (session_id, user_name, auth_id, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)",
        session.session_id,
        session.user_name,
        session.auth_id,
        session.created_at.naive_utc(),
        session.created_at.naive_utc() + chrono::Duration::hours(1) // Example expiration time
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// DELETE FUNCTIONS ///
pub async fn delete_user_by_username(
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM users WHERE user_name = $1", username)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn delete_all_users(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM users").execute(&mut **tx).await?;
    Ok(())
}

pub async fn delete_session_by_id(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM sessions WHERE session_id = $1", session_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn delete_expired_sessions(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query!("DELETE FROM sessions WHERE expires_at < $1", now.naive_utc())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// GETTER FUNCTIONS ///
pub async fn get_user_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT user_name, y1, y2, created_at FROM users WHERE user_name = $1",
        username
    )
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        let y1 = BigUint::from_bytes_be(&row.y1);
        let y2 = BigUint::from_bytes_be(&row.y2);
        let created_at = DateTime::<Utc>::from_utc(row.created_at, Utc);
        Ok(Some(User {
            user_name: row.user_name,
            y1,
            y2,
            created_at: created_at,
        }))
    } else {
        Ok(None)
    }
}

pub async fn get_all_users(
    pool: &PgPool,
) -> Result<Vec<User>, sqlx::Error> {
    let rows = sqlx::query!("SELECT user_name, y1, y2, created_at FROM users")
        .fetch_all(pool)
        .await?;

    let users: Result<Vec<User>, sqlx::Error> = rows
        .into_iter()
        .map(|row| -> Result<User, sqlx::Error> {
            let y1 = BigUint::from_bytes_be(&row.y1);
            let y2 = BigUint::from_bytes_be(&row.y2);
            let created_at = DateTime::<Utc>::from_utc(row.created_at, Utc);
            Ok(User {
                user_name: row.user_name,
                y1,
                y2,
                created_at: created_at,
            })
        })
        .collect();

    Ok(users?)
}

pub async fn count_users(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!("SELECT COUNT(*) as count FROM users")
        .fetch_one(pool)
        .await?;
    Ok(row.count.unwrap_or(0))
}

pub async fn get_session_by_id(
    pool: &PgPool,
    session_id: &str,
) -> Result<Option<Session>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT session_id, user_name, auth_id, created_at, expires_at FROM sessions WHERE session_id = $1",
        session_id
    )
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        Ok(Some(Session {
            session_id: row.session_id,
            user_name: row.user_name,
            auth_id: row.auth_id,
            created_at: DateTime::<Utc>::from_utc(row.created_at, Utc),
        }))
    } else {
        Ok(None)
    }
}

fn main() {}
