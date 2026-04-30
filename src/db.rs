use chrono::{DateTime, Utc};
use num_bigint::BigUint;
use sqlx::{Postgres, Transaction};

#[derive(Clone)]
pub struct User {
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AuthLog {
    pub user_name: String,
    pub auth_id: String,
    pub success: bool,
    pub created_at: DateTime<Utc>,
    pub failure_reason: Option<String>,
}

#[derive(Clone)]
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
        return Err(sqlx::Error::Protocol("username cannot be empty".into()));
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

pub async fn delete_expired_sessions(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query!(
        "DELETE FROM sessions WHERE expires_at < $1",
        now.naive_utc()
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// GETTER FUNCTIONS ///
pub async fn get_user_by_username(
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT user_name, y1, y2, created_at FROM users WHERE user_name = $1",
        username
    )
    .fetch_optional(&mut **tx)
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

pub async fn get_all_users(tx: &mut Transaction<'_, Postgres>) -> Result<Vec<User>, sqlx::Error> {
    let rows = sqlx::query!("SELECT user_name, y1, y2, created_at FROM users")
        .fetch_all(&mut **tx)
        .await?;

    let users: Vec<User> = rows
        .into_iter()
        .map(|row| User {
            user_name: row.user_name,
            y1: BigUint::from_bytes_be(&row.y1),
            y2: BigUint::from_bytes_be(&row.y2),
            created_at: DateTime::<Utc>::from_utc(row.created_at, Utc),
        })
        .collect();

    Ok(users)
}

pub async fn count_users(tx: &mut Transaction<'_, Postgres>) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!("SELECT COUNT(*) as count FROM users")
        .fetch_one(&mut **tx)
        .await?;
    Ok(row.count.unwrap_or(0))
}

pub async fn get_session_by_id(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
) -> Result<Option<Session>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT session_id, user_name, auth_id, created_at, expires_at FROM sessions WHERE session_id = $1",
        session_id
    )
    .fetch_optional(&mut **tx)
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

pub async fn get_login_attempts_by_user(
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
) -> Result<Vec<AuthLog>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT user_name, auth_id, success, created_at, failure_reason FROM auth_logs WHERE user_name = $1",
        username
    )
    .fetch_all(&mut **tx)
    .await?;

    let logs: Vec<AuthLog> = rows
        .into_iter()
        .map(|row| {
            let auth_id = row.auth_id.expect("auth_id should not be null");
            AuthLog {
                user_name: row.user_name,
                auth_id: auth_id,
                success: row.success,
                created_at: DateTime::<Utc>::from_utc(row.created_at, Utc),
                failure_reason: row.failure_reason,
            }
        })
        .collect();

    Ok(logs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenvy::from_filename;
    use sqlx::PgPool;
    use std::env;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    async fn setup_db() -> PgPool {
        from_filename(".env.test").ok();

        let db_url = env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set");

        PgPoolOptions::new()
            .max_connections(2) 
            .acquire_timeout(Duration::from_secs(5))
            .connect(&db_url)
            .await
            .expect("failed to connect to database")
    }

    #[tokio::test]
    async fn test_insert_and_get_user() {
        let pool = setup_db().await;
        let mut tx = pool.begin().await.expect("failed to begin transaction");
        let username_1 = format!("user_{}", uuid::Uuid::new_v4());
        let user_1 = User {
            user_name: username_1.clone(),
            y1: BigUint::from(10u32),
            y2: BigUint::from(20u32),
            created_at: Utc::now(),
        };

        insert_user(&mut tx, user_1)
            .await
            .expect("failed to insert user");
        let fetched = get_user_by_username(&mut tx, &username_1)
            .await
            .expect("failed to get user");
        let fetched = fetched.expect("user not found");
        assert_eq!(fetched.user_name, username_1);

        let username_2 = format!("user_{}", uuid::Uuid::new_v4());
        let user_2 = User {
            user_name: username_2.clone(),
            y1: BigUint::from(10u32),
            y2: BigUint::from(20u32),
            created_at: Utc::now(),
        };

        insert_user(&mut tx, user_2)
            .await
            .expect("failed to insert user");

        let count = count_users(&mut tx).await.expect("failed to count users");
        assert_eq!(count, 2);

        let all_users = get_all_users(&mut tx)
            .await
            .expect("Failed to get all users");

        assert!(all_users.len() == 2);
        let names: Vec<_> = all_users.iter().map(|u| u.user_name.as_str()).collect();

        assert!(names.contains(&username_1.as_str()));
        assert!(names.contains(&username_2.as_str()));

        delete_user_by_username(&mut tx, &username_1)
            .await
            .expect("failed to delete user");

        let fetched = get_user_by_username(&mut tx, &username_1)
            .await
            .expect("failed to get user after deletion");
        assert!(fetched.is_none());

        let count = count_users(&mut tx)
            .await
            .expect("failed to count users after deletion");
        assert_eq!(count, 1);

        tx.rollback().await.expect("failed to rollback transaction");
    }

    #[tokio::test]
    async fn test_insert_and_get_session() {
        let pool = setup_db().await;
        let mut tx = pool.begin().await.expect("failed to begin transaction");
        let user_name = format!("user_{}", uuid::Uuid::new_v4());
        let user = User {
            user_name: user_name.clone(),
            y1: BigUint::from(10u32),
            y2: BigUint::from(20u32),
            created_at: Utc::now(),
        };
        insert_user(&mut tx, user)
            .await
            .expect("failed to insert user");

        let session_id = format!("session_{}", uuid::Uuid::new_v4());

        let session = Session {
            session_id: session_id.clone(),
            user_name: user_name.clone(),
            auth_id: "test_auth".to_string(),
            created_at: Utc::now(),
        };
        insert_session(&mut tx, session)
            .await
            .expect("failed to insert session");

        let auth_log = AuthLog {
            user_name: user_name.clone(),
            auth_id: "test_auth".to_string(),
            success: true,
            created_at: Utc::now(),
            failure_reason: None,
        };
        insert_login_attempt(&mut tx, auth_log)
            .await
            .expect("failed to insert auth log");

        let fetched = get_session_by_id(&mut tx, &session_id)
            .await
            .expect("failed to get session");
        let fetched = fetched.expect("session not found");
        assert_eq!(fetched.session_id, session_id);

        let logs = get_login_attempts_by_user(&mut tx, &user_name)
            .await
            .expect("failed to get login attempts");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].user_name, user_name);
        assert_eq!(logs[0].auth_id, "test_auth");
        assert!(logs[0].success);

        delete_session_by_id(&mut tx, &session_id)
            .await
            .expect("failed to delete session");

        let fetched = get_session_by_id(&mut tx, &session_id)
            .await
            .expect("failed to get session after deletion");
        assert!(fetched.is_none());
        tx.rollback().await.expect("failed to rollback transaction");
    }

    #[tokio::test]
    async fn test_duplicate_user() {
        let pool = setup_db().await;
        let mut tx = pool.begin().await.expect("failed to begin transaction");
        let username = format!("dup_{}", uuid::Uuid::new_v4());
        let user = User {
            user_name: username.clone(),
            y1: BigUint::from(10u32),
            y2: BigUint::from(20u32),
            created_at: Utc::now(),
        };

        insert_user(&mut tx, user.clone())
            .await
            .expect("failed to insert user");

        let result = insert_user(&mut tx, user).await;

        assert!(result.is_err());

        tx.rollback().await.expect("failed to rollback transaction");
    }

    #[tokio::test]
    async fn test_empty_username() {
        let pool = setup_db().await;
        let mut tx = pool.begin().await.expect("failed to begin transaction");
        let user = User {
            user_name: "".to_string(),
            y1: BigUint::from(10u32),
            y2: BigUint::from(20u32),
            created_at: Utc::now(),
        };
        let result = insert_user(&mut tx, user).await;
        assert!(result.is_err());
        tx.rollback().await.expect("failed to rollback transaction");
    }

    #[tokio::test]
    async fn test_missing_user() {
        let pool = setup_db().await;
        let mut tx = pool.begin().await.expect("failed to begin transaction");
        let username = format!("non_existent_user_{}", uuid::Uuid::new_v4());
        let result = get_user_by_username(&mut tx, &username).await;
        let result = result.expect("failed to query database");
        assert!(result.is_none());
        tx.rollback().await.expect("failed to rollback transaction");
    }

    #[tokio::test]
    async fn test_insert_missing_user_in_session() {
        let pool = setup_db().await;
        let mut tx = pool.begin().await.expect("failed to begin transaction");
        let session = Session {
            session_id: format!("orphan_session_{}", uuid::Uuid::new_v4()),
            user_name: format!("non_existent_user_{}", uuid::Uuid::new_v4()),
            auth_id: "test_auth".to_string(),
            created_at: Utc::now(),
        };
        let result = insert_session(&mut tx, session).await;
        assert!(result.is_err());
        tx.rollback().await.expect("failed to rollback transaction");
    }

    #[tokio::test]
    async fn test_delete_user_cascades_sessions() {
        let pool = setup_db().await;
        let mut tx = pool.begin().await.expect("failed to begin transaction");
        let username = format!("cascade_user_{}", uuid::Uuid::new_v4());
        let user = User {
            user_name: username.clone(),
            y1: BigUint::from(10u32),
            y2: BigUint::from(20u32),
            created_at: Utc::now(),
        };
        insert_user(&mut tx, user)
            .await
            .expect("failed to insert user");

        let session_id = format!("cascade_session_{}", uuid::Uuid::new_v4());
        let session = Session {
            session_id: session_id.clone(),
            user_name: username.clone(),
            auth_id: "test_auth".to_string(),
            created_at: Utc::now(),
        };
        insert_session(&mut tx, session)
            .await
            .expect("failed to insert session");

        delete_user_by_username(&mut tx, &username)
            .await
            .expect("failed to delete user");

        let fetched = get_session_by_id(&mut tx, &session_id)
            .await
            .expect("failed to get session after user deletion");
        assert!(fetched.is_none());
        tx.rollback().await.expect("failed to rollback transaction");
    }

    #[tokio::test]
    async fn test_delete_expired_sessions() {
        let pool = setup_db().await;
        let mut tx = pool.begin().await.expect("failed to begin transaction");
        let username = format!("expire_user_{}", uuid::Uuid::new_v4());
        let user = User {
            user_name: username.clone(),
            y1: BigUint::from(10u32),
            y2: BigUint::from(20u32),
            created_at: Utc::now(),
        };
        insert_user(&mut tx, user)
            .await
            .expect("failed to insert user");
        let expired_session = Session {
            session_id: format!("expired_session_{}", uuid::Uuid::new_v4()),
            user_name: username.clone(),
            auth_id: "test_auth".to_string(),
            created_at: Utc::now() - chrono::Duration::hours(2), // Created 2 hours ago
        };
        insert_session(&mut tx, expired_session.clone())
            .await
            .expect("failed to insert expired session");
        let valid_session = Session {
            session_id: format!("valid_session_{}", uuid::Uuid::new_v4()),
            user_name: username.clone(),
            auth_id: "test_auth".to_string(),
            created_at: Utc::now(), // Created now
        };
        insert_session(&mut tx, valid_session.clone())
            .await
            .expect("failed to insert valid session");
        delete_expired_sessions(&mut tx)
            .await
            .expect("failed to delete expired sessions");
        let fetched_expired = get_session_by_id(&mut tx, &expired_session.session_id)
            .await
            .expect("failed to get expired session after deletion");
        assert!(fetched_expired.is_none());
        let fetched_valid = get_session_by_id(&mut tx, &valid_session.session_id)
            .await
            .expect("failed to get valid session after deletion");
        assert!(fetched_valid.is_some());
        tx.rollback().await.expect("failed to rollback transaction");
    }
}
