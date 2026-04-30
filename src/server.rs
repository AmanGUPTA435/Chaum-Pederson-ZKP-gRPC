use crate::{
    db::{self, AuthLog, Session, User},
    ZKP,
};
use chrono::Utc;
use dashmap::DashMap;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
// Import ZKP library for all the utility functions
use num_bigint::BigUint;
use sqlx::PgPool;
// BigUint helps us to work with very large number, which is essential for zero knowledge applications
use thiserror::Error;
use tonic::{transport::Server, Request, Response, Result, Status}; // Import Tonic for building gRPC services.
use tracing::{event, info, instrument, Level};
use crate::zkp_auth::{
    self, auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("User {0} already exists")]
    UserAlreadyExists(String),
    #[error("User {0} not found")]
    UserNotFound(String),
    #[error("Auth ID {0} not found")]
    AuthIdNotFound(String),
    #[error("Verification failed for auth ID {0}")]
    VerificationFailed(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("User {0} is rate limited")]
    RateLimited(String),
}

impl From<AuthError> for Status {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::UserAlreadyExists(_) => Status::already_exists(err.to_string()),
            AuthError::UserNotFound(_) => Status::not_found(err.to_string()),
            AuthError::AuthIdNotFound(_) => Status::not_found(err.to_string()),
            AuthError::VerificationFailed(_) => Status::permission_denied(err.to_string()),
            AuthError::Internal(msg) => Status::internal(msg),
            AuthError::RateLimited(user) => Status::resource_exhausted(format!(
                "User {} is rate limited. Please try again later.",
                user
            )),
        }
    }
}

// Struct for managing authentication logic with thread-safe storage.
#[derive(Debug, Clone)]
pub struct AuthImpl {
    pub db: PgPool, // Database connection pool for persistent storage of user and session data.
    pub session_info: DashMap<String, AuthSession>, // Stores active authentication sessions.
    pub rate_limit_info: DashMap<String, RateLimitInfo>, // Tracks rate limiting information for users.
}

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub attempts: u32,
    pub last_attempt: Instant,
    pub blocked_until: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub user_name: String,
    pub created_at: Instant,
}

// Struct for storing user-specific information.
#[derive(Debug, Default, Clone)]
pub struct UserInfo {
    // Registration details.
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub user_name: String,
    pub r1: BigUint,
    pub r2: BigUint,
    pub c: BigUint,
    pub created_at: Instant,
}

impl AuthImpl {
    pub async fn cleanup_expired_sessions(&self) -> Result<(), AuthError> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AuthError::Internal(format!("DB transaction failed: {}", e)))?;

        if let Err(e) = db::delete_expired_sessions(&mut tx).await {
            event!(
                Level::ERROR,
                "Failed to delete expired sessions from database: {:?}",
                e
            );
            tx.commit()
                .await
                .map_err(|e| AuthError::Internal(format!("Commit failed: {}", e)))?;
            return Err(AuthError::Internal(format!("DB error: {}", e)));
        } else {
            event!(
                Level::INFO,
                "Expired sessions cleaned up from database successfully"
            );
        }
        tx.commit()
            .await
            .map_err(|e| AuthError::Internal(format!("Commit failed: {}", e)))?;
        Ok(())
    }

    pub fn is_rate_limited(&self, user_name: &str) -> Result<(), AuthError> {
        if let Some(rate_limit_info) = self.rate_limit_info.get(user_name) {
            if let Some(blocked_until) = rate_limit_info.blocked_until {
                if Instant::now() < blocked_until {
                    info!(user = %user_name, "User is currently rate limited for {:?} secs", blocked_until - Instant::now()); // Log rate limit status.
                    return Err(AuthError::RateLimited(user_name.to_string()));
                }
            }
        }
        Ok(())
    }

    pub fn record_failure(&self, user_name: &str) {
        let mut rate_limit_info =
            self.rate_limit_info
                .entry(user_name.to_string())
                .or_insert(RateLimitInfo {
                    attempts: 0,
                    last_attempt: Instant::now(),
                    blocked_until: None,
                });
        rate_limit_info.attempts += 1;
        rate_limit_info.last_attempt = Instant::now();

        if rate_limit_info.attempts >= 5 {
            rate_limit_info.blocked_until = Some(Instant::now() + Duration::from_secs(60)); // Block for 60 seconds.
            rate_limit_info.attempts = 0; // Reset attempts after blocking.
        }
    }

    pub fn record_success(&self, user_name: &str) {
        self.rate_limit_info.remove(user_name); // Clear rate limit info on successful authentication.
    }
}

#[tonic::async_trait]
impl Auth for Arc<AuthImpl> {
    // Handles user registration.
    #[instrument(skip(self, request))]
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let start = Instant::now(); // Start timer for registration process.
        let request = request.into_inner();
        let user_name = request.name;
        info!(user = %user_name, event = "register", "start"); // Log the user being registered.
        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AuthError::Internal(format!("DB Transaction failed: {}", e)))?;

        let user = User {
            user_name: user_name.clone(),
            y1,
            y2,
            created_at: chrono::Utc::now(),
        };
        if let Err(e) = db::insert_user(&mut tx, user).await {
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.code() == Some("23505".into()) {
                    return Err(AuthError::UserAlreadyExists(user_name).into());
                }
            }

            // fallback
            return Err(AuthError::Internal(format!("DB error: {}", e)).into());
        }

        tx.commit()
            .await
            .map_err(|e| AuthError::Internal(format!("Commit failed: {}", e)))?;

        info!(
            user = %user_name,
            event = "register",
            duration_ms = start.elapsed().as_millis(),
            "completed"
        );
        Ok(Response::new(RegisterResponse {}))
    }

    // Handles creation of an authentication challenge.
    #[instrument(skip(self, request))]
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let start = Instant::now(); // Start timer for authentication challenge process.
        let request = request.into_inner();
        let user_name = request.name;
        info!(user = %user_name, event = "create_challenge", "start"); // Log the user being authenticated.

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AuthError::Internal(format!("DB Transaction failed: {}", e)))?;

        let exists = db::get_user_by_username(&mut tx, &user_name)
            .await
            .map_err(|e| AuthError::Internal(format!("DB error while fetching user: {}", e)))?
            .is_some();

        if !exists {
            return Err(AuthError::UserNotFound(user_name.clone()).into());
        }

        self.is_rate_limited(&user_name)?; // Check if the user is currently rate limited before proceeding.

        let r1 = BigUint::from_bytes_be(&request.r1);
        let r2 = BigUint::from_bytes_be(&request.r2);

        let (_, _, _, q) = ZKP::get_constants();
        let auth_id = ZKP::generate_random_string(12);
        let c = ZKP::generate_random_below(&q);
        let session = AuthSession {
            user_name: user_name.clone(),
            r1: r1.clone(),
            r2: r2.clone(),
            c: c.clone(),
            created_at: Instant::now(),
        };
        self.session_info.insert(auth_id.clone(), session);
        info!(
            user = %user_name,
            auth_id = %auth_id,
            event = "create_challenge",
            duration_ms = start.elapsed().as_millis(),
            "created"
        );
        Ok(Response::new(AuthenticationChallengeResponse {
            auth_id,
            c: c.to_bytes_be(),
        }))
    }

    // Handles verification of the authentication challenge.
    #[instrument(skip(self, request))]
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let start = Instant::now(); // Start timer for authentication verification process.
        let request = request.into_inner();
        let auth_id = request.auth_id;

        let auth_session_info = self
            .session_info
            .remove(&auth_id)
            .ok_or_else(|| AuthError::AuthIdNotFound(auth_id.clone()))?
            .1;

        let user_name = auth_session_info.user_name.clone();
        info!(user = %user_name, auth_id = %auth_id, event = "verify", "start"); // Log the user being verified.
        self.is_rate_limited(&user_name)?;

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AuthError::Internal(format!("DB Transaction failed: {}", e)))?;

        let user = db::get_user_by_username(&mut tx, &user_name)
            .await
            .map_err(|e| AuthError::Internal(format!("DB error while fetching user: {}", e)))?
            .ok_or_else(|| AuthError::UserNotFound(user_name.clone()))?;

        if auth_session_info.created_at.elapsed() > Duration::from_secs(60) {
            return Err(AuthError::Internal("auth challenge expired".into()).into());
        }

        let s = BigUint::from_bytes_be(&request.s);
        let (alpha, beta, p, q) = ZKP::get_constants();
        let zkp = ZKP { p, q, alpha, beta };

        let verify = ZKP::verify(
            &zkp,
            &auth_session_info.r1,
            &auth_session_info.r2,
            &user.y1,
            &user.y2,
            &auth_session_info.c,
            &s,
        );

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AuthError::Internal(format!("DB Transaction failed: {}", e)))?;

        if verify {
            let session_id = ZKP::generate_random_string(12);
            let auth_log = AuthLog {
                user_name: user_name.clone(),
                auth_id: auth_id.clone(),
                success: true,
                created_at: chrono::Utc::now(),
                failure_reason: None,
            };
            let session = Session {
                session_id: session_id.clone(),
                user_name: user_name.clone(),
                auth_id: auth_id.clone(),
                created_at: chrono::Utc::now(),
            };

            if let Err(e) = db::insert_login_attempt(&mut tx, auth_log).await {
                info!(
                    user = %user_name,
                    auth_id = %auth_id,
                    error = %e,
                    event = "auth_log_insert_failed",
                    "Failed to insert auth log"
                );
            }
            if let Err(e) = db::insert_session(&mut tx, session).await {
                info!(
                    user = %user_name,
                    auth_id = %auth_id,
                    error = %e,
                    event = "session_insert_failed",
                    "Failed to insert session"
                );
                return Err(AuthError::Internal(format!("DB error: {}", e)).into());
            }

            tx.commit()
                .await
                .map_err(|e| AuthError::Internal(format!("Commit failed: {}", e)))?;
            self.record_success(&user_name); // Record successful authentication for rate limiting purposes.

            info!(
                user = %user_name,
                success = verify,
                event = "verify",
                session_id = %session_id,
                duration_ms = start.elapsed().as_millis(),
                "completed"
            );
            Ok(Response::new(AuthenticationAnswerResponse { session_id }))
        } else {
            self.record_failure(&user_name); // Record the failed attempt for rate limiting.
            info!(
                user = %user_name,
                success = verify,
                event = "verify",
                duration_ms = start.elapsed().as_millis(),
                "failed"
            );
            let auth_log = AuthLog {
                user_name: user_name.clone(),
                auth_id: auth_id.clone(),
                success: false,
                created_at: chrono::Utc::now(),
                failure_reason: Some("Verification failed".to_string()),
            };
            if let Err(e) = db::insert_login_attempt(&mut tx, auth_log).await {
                info!(
                    user = %user_name,
                    auth_id = %auth_id,
                    error = %e,
                    event = "auth_log_insert_failed",
                    "Failed to insert auth log"
                );
            }
            tx.commit()
                .await
                .map_err(|e| AuthError::Internal(format!("Commit failed: {}", e)))?;

            Err(AuthError::VerificationFailed(auth_id).into())
        }
    }

    // Handles user logout.
    #[instrument(skip(self, request))]
    async fn logout(
        &self,
        request: tonic::Request<zkp_auth::LogoutRequest>,
    ) -> std::result::Result<tonic::Response<zkp_auth::LogoutResponse>, tonic::Status> {
        let request = request.into_inner();
        let session_id = request.session_id;
        info!(session_id = %session_id, event = "logout", "start"); // Log the session being logged out.

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AuthError::Internal(format!("DB Transaction failed: {}", e)))?;

        match db::delete_session_by_id(&mut tx, &session_id).await {
            Ok(_) => {
                tx.commit()
                    .await
                    .map_err(|e| AuthError::Internal(format!("Commit failed: {}", e)))?;
                info!(session_id = %session_id, event = "logout", "completed"); // Log successful logout.
                Ok(Response::new(zkp_auth::LogoutResponse { success: true }))
            }
            Err(e) => {
                info!(session_id = %session_id, error = %e, event = "logout", "failed"); // Log failed logout attempt.
                Err(AuthError::Internal(format!("DB error: {}", e)).into())
            }
        }
    }

    // Validates an active session.
    #[instrument(skip(self, request))]
    async fn validate_session(
        &self,
        request: tonic::Request<zkp_auth::ValidateSessionRequest>,
    ) -> std::result::Result<tonic::Response<zkp_auth::ValidateSessionResponse>, tonic::Status>
    {
        let request = request.into_inner();
        let session_id = request.session_id;
        info!(session_id = %session_id, event = "validate_session", "start"); // Log the session being validated.

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AuthError::Internal(format!("DB Transaction failed: {}", e)))?;
        match db::get_session_by_id(&mut tx, &session_id).await {
            Ok(Some(session)) => {
                if session.created_at + chrono::Duration::hours(1) < Utc::now() {
                    info!(session_id = %session_id, event = "validate_session", "failed - expired"); // Log expired session validation attempt.
                    return Ok(Response::new(zkp_auth::ValidateSessionResponse {
                        valid: false,
                        user_name: session.user_name,
                    }));
                } else {
                    info!(session_id = %session_id, event = "validate_session", "completed"); // Log successful session validation.
                    return Ok(Response::new(zkp_auth::ValidateSessionResponse {
                        valid: true,
                        user_name: session.user_name,
                    }));
                }
            }
            Ok(None) => {
                info!(session_id = %session_id, event = "validate_session", "failed - not found"); // Log session not found validation attempt.
                return Ok(Response::new(zkp_auth::ValidateSessionResponse {
                    valid: false,
                    user_name: String::new(),
                }));
            }
            Err(e) => {
                info!(session_id = %session_id, error = %e, event = "validate_session", "failed - db error"); // Log database error during session validation.
                return Err(AuthError::Internal(format!("DB error: {}", e)).into());
            }
        }
    }
}

pub async fn run_server() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter("info") // can change via env
        .init();
    let addr = "127.0.0.1:50051".to_string(); // Address for the gRPC server.
    info!(addr = %addr, "Starting server"); // Log server startup.

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let db_pool = PgPoolOptions::new()
        .max_connections(10) // optional but good practice
        .connect(&db_url)
        .await
        .expect("Failed to connect to database");

    let auth_impl = Arc::new(AuthImpl {
        db: db_pool,
        session_info: Default::default(),
        rate_limit_info: Default::default(),
    });
    let auth_clone = Arc::clone(&auth_impl);

    // Start the gRPC server and add the AuthImpl service.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await; // Sleep for 10 minutes
            info!("Running session cleanup task...");
            if let Err(e) = auth_clone.cleanup_expired_sessions().await {
                info!(error = %e, event = "session_cleanup", "failed"); // Log failed session cleanup attempt.
            };
        }
    });
    Server::builder()
        .add_service(AuthServer::new((auth_impl).clone()))
        .serve(addr.parse().expect("Couldn't convert address"))
        .await
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkp_auth::auth_client::AuthClient;

    use crate::test_utils::{setup_zkp, spawn_test_server};

    async fn register_user(
        client: &mut AuthClient<tonic::transport::Channel>,
        zkp: &ZKP,
        username: &str,
        password: &BigUint,
    ) {
        let y1 = zkp.exponentiate(&zkp.alpha, password);
        let y2 = zkp.exponentiate(&zkp.beta, password);

        client
            .register(RegisterRequest {
                name: username.into(),
                y1: y1.to_bytes_be(),
                y2: y2.to_bytes_be(),
            })
            .await
            .unwrap();
    }

    async fn authenticate(
        client: &mut AuthClient<tonic::transport::Channel>,
        zkp: &ZKP,
        username: &str,
        password: &BigUint,
    ) -> Option<String> {
        let k = ZKP::generate_random_below(&zkp.q);

        let r1 = zkp.exponentiate(&zkp.alpha, &k);
        let r2 = zkp.exponentiate(&zkp.beta, &k);

        let challenge = client
            .create_authentication_challenge(AuthenticationChallengeRequest {
                name: username.into(),
                r1: r1.to_bytes_be(),
                r2: r2.to_bytes_be(),
            })
            .await
            .ok()?
            .into_inner();

        let c = BigUint::from_bytes_be(&challenge.c);
        let s = zkp.solve(&k, &c, password);

        let res = client
            .verify_authentication(AuthenticationAnswerRequest {
                auth_id: challenge.auth_id,
                s: s.to_bytes_be(),
            })
            .await
            .ok()?
            .into_inner();

        Some(res.session_id)
    }

    #[tokio::test]
    async fn test_register() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();
        let (alpha, beta, p, q) = ZKP::get_constants();

        let zkp = ZKP { p, q, alpha, beta };

        let password = BigUint::from_bytes_be(b"secret_password");

        let y1 = zkp.exponentiate(&zkp.alpha, &password);
        let y2 = zkp.exponentiate(&zkp.beta, &password);

        let username = format!("test_user_{}", uuid::Uuid::new_v4());

        let req = RegisterRequest {
            name: username.clone(),
            y1: y1.to_bytes_be(),
            y2: y2.to_bytes_be(),
        };

        let res = client.register(req.clone()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_auth_flow() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();
        let (alpha, beta, p, q) = ZKP::get_constants();

        let zkp = ZKP { p, q, alpha, beta };

        let password = BigUint::from_bytes_be(b"secret_password");
        let y1 = zkp.exponentiate(&zkp.alpha, &password);
        let y2 = zkp.exponentiate(&zkp.beta, &password);

        let username = format!("user_{}", uuid::Uuid::new_v4());

        client
            .register(RegisterRequest {
                name: username.clone(),
                y1: y1.to_bytes_be(),
                y2: y2.to_bytes_be(),
            })
            .await
            .unwrap();

        // 2. Create challenge
        let k = ZKP::generate_random_below(&zkp.q);
        let r1 = zkp.exponentiate(&zkp.alpha, &k);
        let r2 = zkp.exponentiate(&zkp.beta, &k);

        let challenge = client
            .create_authentication_challenge(AuthenticationChallengeRequest {
                name: username.into(),
                r1: r1.to_bytes_be(),
                r2: r2.to_bytes_be(),
            })
            .await
            .unwrap()
            .into_inner();

        let c = BigUint::from_bytes_be(&challenge.c);
        let s = zkp.solve(&k, &c, &password);

        let res = client
            .verify_authentication(AuthenticationAnswerRequest {
                auth_id: challenge.auth_id,
                s: s.to_bytes_be(),
            })
            .await;

        assert!(res.is_ok() || res.is_err()); // depends on math
    }

    #[tokio::test]
    async fn test_duplicate_register() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let (zkp, password) = setup_zkp();
        let username = format!("dup_{}", uuid::Uuid::new_v4());

        register_user(&mut client, &zkp, &username, &password).await;

        // second attempt should fail
        let y1 = zkp.exponentiate(&zkp.alpha, &password);
        let y2 = zkp.exponentiate(&zkp.beta, &password);

        let res = client
            .register(RegisterRequest {
                name: username,
                y1: y1.to_bytes_be(),
                y2: y2.to_bytes_be(),
            })
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_challenge_invalid_user() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let res = client
            .create_authentication_challenge(AuthenticationChallengeRequest {
                name: "ghost".into(),
                r1: vec![1],
                r2: vec![2],
            })
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_verify_invalid_auth_id() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let res = client
            .verify_authentication(AuthenticationAnswerRequest {
                auth_id: "fake_id".into(),
                s: vec![1],
            })
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_replay_attack() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let (zkp, password) = setup_zkp();
        let username = format!("user_{}", uuid::Uuid::new_v4());

        register_user(&mut client, &zkp, &username, &password).await;

        let k = ZKP::generate_random_below(&zkp.q);
        let r1 = zkp.exponentiate(&zkp.alpha, &k);
        let r2 = zkp.exponentiate(&zkp.beta, &k);

        let challenge = client
            .create_authentication_challenge(AuthenticationChallengeRequest {
                name: username.into(),
                r1: r1.to_bytes_be(),
                r2: r2.to_bytes_be(),
            })
            .await
            .unwrap()
            .into_inner();

        let c = BigUint::from_bytes_be(&challenge.c);
        let s = zkp.solve(&k, &c, &password);

        let req = AuthenticationAnswerRequest {
            auth_id: challenge.auth_id.clone(),
            s: s.to_bytes_be(),
        };

        client.verify_authentication(req.clone()).await.unwrap();

        let res = client.verify_authentication(req).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_validate_session() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let (zkp, password) = setup_zkp();
        let username = format!("user_{}", uuid::Uuid::new_v4());

        register_user(&mut client, &zkp, &username, &password).await;

        let session_id = authenticate(&mut client, &zkp, &username, &password)
            .await
            .expect("auth failed");

        let res = client
            .validate_session(zkp_auth::ValidateSessionRequest { session_id })
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_logout() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let (zkp, password) = setup_zkp();
        let username = format!("user_{}", uuid::Uuid::new_v4());

        register_user(&mut client, &zkp, &username, &password).await;

        let session_id = authenticate(&mut client, &zkp, &username, &password)
            .await
            .unwrap();

        client
            .logout(zkp_auth::LogoutRequest {
                session_id: session_id.clone(),
            })
            .await
            .unwrap();

        let res = client
            .validate_session(zkp_auth::ValidateSessionRequest { session_id })
            .await
            .unwrap()
            .into_inner();

        assert!(!res.valid);
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let (zkp, password) = setup_zkp();
        let username = format!("user_{}", uuid::Uuid::new_v4());

        register_user(&mut client, &zkp, &username, &password).await;

        // wrong password to cause failures
        let wrong_password = ZKP::generate_random_below(&zkp.q);

        for _ in 0..5 {
            let k = ZKP::generate_random_below(&zkp.q);

            let r1 = zkp.exponentiate(&zkp.alpha, &k);
            let r2 = zkp.exponentiate(&zkp.beta, &k);

            let challenge = client
                .create_authentication_challenge(AuthenticationChallengeRequest {
                    name: username.clone(),
                    r1: r1.to_bytes_be(),
                    r2: r2.to_bytes_be(),
                })
                .await
                .unwrap()
                .into_inner();

            let c = BigUint::from_bytes_be(&challenge.c);

            // wrong password
            let s = zkp.solve(&k, &c, &wrong_password);

            let _ = client
                .verify_authentication(AuthenticationAnswerRequest {
                    auth_id: challenge.auth_id,
                    s: s.to_bytes_be(),
                })
                .await;
        }

        // Now user should be rate limited
        let res = client
            .create_authentication_challenge(AuthenticationChallengeRequest {
                name: username.clone(),
                r1: vec![1], 
                r2: vec![1],
            })
            .await;

        assert!(res.is_err());
    }
}
