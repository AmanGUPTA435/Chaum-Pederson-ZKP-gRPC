use std::time::Instant; 
use chaum_pederson_rust::ZKP; use dashmap::DashMap;
// Import ZKP library for all the utility functions
use num_bigint::BigUint; // BigUint helps us to work with very large number, which is essential for zero knowledge applications
use tonic::{transport::Server, Request, Response, Result, Status}; // Import Tonic for building gRPC services.
use thiserror::Error;
use tracing::info;
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse,
    AuthenticationChallengeRequest, AuthenticationChallengeResponse,
    RegisterRequest, RegisterResponse,
};

// Include generated gRPC module.
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

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
    #[error("Mutex poisoned")]
    MutexPoisoned,
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<AuthError> for Status {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::UserAlreadyExists(_) => Status::already_exists(err.to_string()),
            AuthError::UserNotFound(_) => Status::not_found(err.to_string()),
            AuthError::AuthIdNotFound(_) => Status::not_found(err.to_string()),
            AuthError::VerificationFailed(_) => Status::permission_denied(err.to_string()),
            AuthError::MutexPoisoned => Status::internal("Internal server error"),
            AuthError::Internal(msg) => Status::internal(msg),
        }
    }
}

// Struct for managing authentication logic with thread-safe storage.
#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: DashMap<String, UserInfo>, // Stores user registration and authentication data.
    pub post_auth_info: DashMap<String, SessionInfo>, // Maps auth IDs to usernames.
    pub session_info: DashMap<String, AuthSession>, // Stores active authentication sessions.
}

#[derive(Debug)]
pub struct SessionInfo {
    pub user_name: String,
    pub created_at: Instant,
}

// Struct for storing user-specific information.
#[derive(Debug, Default)]
pub struct UserInfo {
    // Registration details.
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
}

#[derive(Debug, Default)]
pub struct AuthSession {
    pub user_name: String,
    pub r1: BigUint,
    pub r2: BigUint,
    pub c: BigUint
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    // Handles user registration.
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        info!("Processing register: {:?}", request); // Log the incoming request.
        
        let request = request.into_inner();
        let user_name = request.name;
        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        let user_info = &self.user_info;
        if user_info.contains_key(&user_name) {
            return Err(AuthError::UserAlreadyExists(user_name).into());
        }

        let mut user = UserInfo::default();
        user.user_name = user_name.clone();
        user.y1 = y1;
        user.y2 = y2;

        user_info.insert(user_name, user);

        Ok(Response::new(RegisterResponse {}))
    }
    
    // Handles creation of an authentication challenge.
    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        info!("Processing authentication challenge: {:?}", request); // Log the incoming request.
        
        let request = request.into_inner();
        let user_name = request.name;
        if !self.user_info.contains_key(&user_name) {
            return Err(AuthError::UserNotFound(user_name).into());
        }
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
        };
        self.session_info.insert(auth_id.clone(), session);

        Ok(Response::new(AuthenticationChallengeResponse {
            auth_id,
            c: c.to_bytes_be(),
        }))
    }
    
    // Handles verification of the authentication challenge.
    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        info!("Processing verification: {:?}", request); // Log the incoming request.

        let request = request.into_inner();
        let auth_id = request.auth_id;

        let auth_session_info = {
            let map = &self.session_info;
            map.remove(&auth_id)
                .ok_or_else(|| AuthError::AuthIdNotFound(auth_id.clone()))?.1
        };
        let user_name = auth_session_info.user_name.clone();
        let user = {
            let map = &self.user_info;
            map.get(&user_name)
                .ok_or_else(|| AuthError::UserNotFound(user_name.clone()))?
        };

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

        if verify {
            let session_id = ZKP::generate_random_string(12);
            self.post_auth_info.insert(session_id.clone(), SessionInfo {
                user_name: user_name.clone(),
                created_at: Instant::now(),
            });
            Ok(Response::new(AuthenticationAnswerResponse { session_id }))
        } else {
            Err(AuthError::VerificationFailed(auth_id).into())
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info") // can change via env
        .init();
    let addr = "127.0.0.1:50051".to_string(); // Address for the gRPC server.
    info!("Starting server at {}", addr); // Log server startup.

    let auth_impl = AuthImpl::default(); // Initialize the AuthImpl service.
    
    // Start the gRPC server and add the AuthImpl service.
    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("Couldn't convert address"))
        .await
        .unwrap();
}
