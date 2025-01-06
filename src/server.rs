use std::{collections::HashMap, sync::Mutex}; 
use chaum_pederson_rust::ZKP; // Import ZKP library for all the utility functions
use num_bigint::BigUint; // BigUint helps us to work with very large number, which is essential for zero knowledge applications
use tonic::{transport::Server, Request, Response, Result, Status}; // Import Tonic for building gRPC services.
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

// Struct for managing authentication logic with thread-safe storage.
#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>, // Stores user registration and authentication data.
    pub auth_id_to_user: Mutex<HashMap<String, String>>, // Maps auth IDs to usernames.
}

// Struct for storing user-specific information.
#[derive(Debug, Default)]
pub struct UserInfo {
    // Registration details.
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    // Challenge details.
    pub r1: BigUint,
    pub r2: BigUint,
    // Verification details.
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String, // Session ID upon successful authentication.
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    // Handles user registration.
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing register: {:?}", request); // Log the incoming request.
        
        // Extract registration data.
        let request = request.into_inner();
        let user_name = request.name;
        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        // Populate UserInfo struct and store in user_info.
        let mut user_info = UserInfo::default();
        user_info.user_name = user_name.clone();
        user_info.y1 = y1;
        user_info.y2 = y2;

        // Insert user into the HashMap (thread-safe).
        self.user_info.lock().unwrap().insert(user_name, user_info);

        // Return a successful response.
        Ok(Response::new(RegisterResponse {}))
    }
    
    // Handles creation of an authentication challenge.
    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing authentication challenge: {:?}", request); // Log the incoming request.
        
        // Extract challenge request data.
        let request = request.into_inner();
        let user_name = request.name;
        let r1 = BigUint::from_bytes_be(&request.r1);
        let r2 = BigUint::from_bytes_be(&request.r2);

        // Check if the user exists in user_info.
        let mut user_info = self.user_info.lock().unwrap();
        if let Some(user) = user_info.get_mut(&user_name) {
            // Generate a random challenge value c and an authentication ID.
            let (_, _, _, q) = ZKP::get_constants();
            let auth_id = ZKP::generate_random_string(12);
            let c = ZKP::generate_random_below(&q);

            // Store the challenge details in the user's info.
            user.r1 = r1.clone();
            user.r2 = r2.clone();
            user.c = c.clone();

            // Map auth_id to username.
            self.auth_id_to_user.lock().unwrap().insert(auth_id.clone(), user_name);

            // Return the challenge response.
            return Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }));
        } else {
            // If user not found, return a not_found error.
            return Err(Status::not_found("User not found"));
        }
    }
    
    // Handles verification of the authentication challenge.
    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing verification: {:?}", request); // Log the incoming request.

        // Extract verification request data.
        let request = request.into_inner();
        let auth_id = request.auth_id;

        // Check if the auth ID exists in the mapping.
        let auth_id_map = self.auth_id_to_user.lock().unwrap();
        if let Some(user_name) = auth_id_map.get(&auth_id) {
            // Retrieve user details for the corresponding username.
            let mut user_info = self.user_info.lock().unwrap();
            let user_info = user_info.get_mut(user_name).unwrap();

            // Verify the solution to the challenge.
            let s = BigUint::from_bytes_be(&request.s);
            let (alpha, beta, p, q) = ZKP::get_constants();
            let zkp = ZKP { p, q, alpha, beta };

            let verify = ZKP::verify(
                &zkp,
                &user_info.r1,
                &user_info.r2,
                &user_info.y1,
                &user_info.y2,
                &user_info.c,
                &s,
            );

            if verify {
                // If verification succeeds, generate a session ID.
                let session_id = ZKP::generate_random_string(12);
                user_info.session_id = session_id.clone();

                // Return a successful response with the session ID.
                return Ok(Response::new(AuthenticationAnswerResponse { session_id }));
            } else {
                // Return an error if verification fails.
                return Err(Status::permission_denied(format!(
                    "Auth ID: {} sent a bad solution to the challenge",
                    auth_id
                )));
            }
        } else {
            // If auth ID is not found, return a not_found error.
            return Err(Status::not_found(format!("Auth ID {} not found", auth_id)));
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string(); // Address for the gRPC server.
    println!("Running the server: {}", addr); // Log server startup.

    let auth_impl = AuthImpl::default(); // Initialize the AuthImpl service.
    
    // Start the gRPC server and add the AuthImpl service.
    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("Couldn't convert address"))
        .await
        .unwrap();
}
