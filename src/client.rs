use clap::{Parser, Subcommand};
use num_bigint::BigUint;
use std::time::Instant;
use tonic::transport::Channel;
use tracing::{info, instrument};
// Import BigUint for handling large integers.
use crate::ZKP;
use crate::zkp_auth::{
    self, auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    RegisterRequest,
};

#[derive(Parser)]
#[command(name = "ZKP Client", about = "A client for ZKP authentication server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Register { username: String, password: String },
    Authenticate { username: String, password: String },
    Logout { session_id: String },
    ValidateSession { session_id: String },
}

#[instrument(skip(client, zkp, password))]
async fn register_user(
    username: String,
    password: String,
    zkp: &ZKP,
    client: &mut AuthClient<Channel>,
) {
    info!(user = %username, event = "register", "start"); // Log registration attempt.
    let start = Instant::now(); // Start timer for registration process.
    let password = BigUint::from_bytes_be(password.trim().as_bytes()); // Convert password to BigUint for ZKP computations.
                                                                       // Compute y1 = alpha^password mod p and y2 = beta^password mod p for registration.
    let y1 = zkp.exponentiate(&zkp.alpha, &password);
    let y2 = zkp.exponentiate(&zkp.beta, &password);

    // Create a registration request with the computed values.
    let request = RegisterRequest {
        name: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    // Send the registration request to the server and handle response.
    match client.register(request).await {
        Ok(_) => {
            info!(user = %username, event = "register", duration_ms = start.elapsed().as_millis(), "completed")
        } // Log server's response.
        Err(e) => {
            info!(user = %username, error = %e, event = "register", duration_ms = start.elapsed().as_millis(), "failed"); // Log registration failure.
            return;
        }
    }
}

#[instrument(skip(client, zkp, password))]
async fn authenticate_user(
    username: String,
    password: String,
    zkp: &ZKP,
    client: &mut AuthClient<Channel>,
) {
    info!(user = %username, event = "create_challenge", "start"); // Log authentication attempt.
    let start = Instant::now(); // Start timer for authentication process.
    let password = BigUint::from_bytes_be(password.trim().as_bytes()); // Convert password to BigUint for ZKP computations.
                                                                       // Generate a random challenge value k < q.
    let k = ZKP::generate_random_below(&zkp.q);

    // Compute r1 = alpha^k mod p and r2 = beta^k mod p as part of the authentication challenge.
    let r1 = zkp.exponentiate(&zkp.alpha, &k);
    let r2 = zkp.exponentiate(&zkp.beta, &k);

    // Create an authentication challenge request.
    let request = AuthenticationChallengeRequest {
        name: username.clone(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    // Send the challenge request to the server and handle response.
    let response: tonic::Response<zkp_auth::AuthenticationChallengeResponse> =
        match client.create_authentication_challenge(request).await {
            Ok(response) => response, // Log server's response.
            Err(e) => {
                info!(error = %e, user = %username, event = "create_challenge", duration_ms = start.elapsed().as_millis(), "failed"); // Log challenge creation failure.
                return;
            }
        };
    let response = response.into_inner();
    info!(user = %username, auth_id = ?response.auth_id, event = "create_challenge", duration_ms = start.elapsed().as_millis(), "completed"); // Log server's response.
                                                                                                                                              // Extract challenge ID and value c from server's response.
    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    // Compute s = k + c * password mod q as part of the challenge solution.
    let s = zkp.solve(&k, &c, &password);

    // Create an authentication answer request with the computed s value.
    let request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };
    info!(user = %username, event = "verify", "start");
    // Send the answer to the server for verification and handle response.
    let reponse = match client.verify_authentication(request).await {
        // Print server's verification result.
        Ok(response) => response.into_inner(),
        Err(e) => {
            info!(error = %e, user = %username, event = "verify", duration_ms = start.elapsed().as_millis(), "failed"); // Log verification failure.
            return;
        }
    };
    info!(
        user = %username,
        event = "verify",
        session_id = ?reponse.session_id,
        duration_ms = start.elapsed().as_millis(),
        "completed"
    );
}

#[instrument(skip(client))]
async fn logout_user(session_id: String, client: &mut AuthClient<Channel>) {
    info!(session_id = %session_id, event = "logout", "start"); // Log logout attempt.
    let request = zkp_auth::LogoutRequest {
        session_id: session_id.clone(),
    };

    match client.logout(request).await {
        Ok(_) => info!(session_id = %session_id, event = "logout", "completed"),
        Err(e) => {
            info!(session_id = %session_id, error = %e, event = "logout", "failed");
            return;
        }
    };
    info!(session_id = %session_id, event = "logout", "completed")
}

#[instrument(skip(client))]
async fn validate_session(session_id: String, client: &mut AuthClient<Channel>) {
    info!(session_id = %session_id, event = "validate_session", "start"); // Log session validation attempt.
    let request = zkp_auth::ValidateSessionRequest {
        session_id: session_id.clone(),
    };
    match client.validate_session(request).await {
        Ok(_) => {
            info!(session_id = %session_id, event = "validate_session", "completed");
        }
        Err(e) => {
            info!(session_id = %session_id, error = %e, event = "validate_session", "failed");
            return;
        }
    }
}

pub async fn run_client() {
    tracing_subscriber::fmt()
        .with_env_filter("info") // can change via env
        .init();
    let cli = Cli::parse(); // Parse command-line arguments.

    // Retrieve constants like alpha, beta, p, and q used for Zero-Knowledge Proofs.
    let (alpha, beta, p, q) = ZKP::get_constants();

    // Initialize the ZKP struct with constants.
    let zkp = ZKP { p, q, alpha, beta };

    // Connect to the authentication server via gRPC.
    let mut client = match AuthClient::connect("http://127.0.0.1:50051").await {
        Ok(client) => client,
        Err(e) => {
            info!(error = %e, event = "connect", "failed to connect to server");
            return;
        }
    };

    info!(event = "connect", "Client started listening"); // Debug message.
    match cli.command {
        Commands::Register { username, password } => {
            register_user(username, password, &zkp, &mut client).await; // Handle user registration.
        }
        Commands::Authenticate { username, password } => {
            authenticate_user(username, password, &zkp, &mut client).await; // Handle user authentication.
        }
        Commands::Logout { session_id } => {
            logout_user(session_id, &mut client).await; // Handle user logout.
        }
        Commands::ValidateSession { session_id } => {
            validate_session(session_id, &mut client).await; // Handle session validation.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use num_bigint::BigUint;
    use clap::Parser;
    use num_traits::Zero;
    use crate::test_utils::{setup_zkp, spawn_test_server};

    #[test]
    fn test_register_request_construction() {
        let (alpha, beta, p, q) = ZKP::get_constants();
        let zkp = ZKP { p, q, alpha, beta };

        let password = "secret";
        let password_big = BigUint::from_bytes_be(password.as_bytes());

        let y1 = zkp.exponentiate(&zkp.alpha, &password_big);
        let y2 = zkp.exponentiate(&zkp.beta, &password_big);

        assert!(!y1.is_zero());
        assert!(!y2.is_zero());
    }

    #[test]
    fn test_cli_register_parse() {
        let cli = Cli::parse_from(["app", "register", "user", "pass"]);

        match cli.command {
            Commands::Register { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass");
            }
            _ => panic!("wrong command"),
        }
    }

    #[tokio::test]
    async fn test_client_auth_flow() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let (zkp, _) = setup_zkp();
        let username = format!("user_{}", Uuid::new_v4());

        register_user(username.clone(), "pass".into(), &zkp, &mut client).await;
        authenticate_user(username, "pass".into(), &zkp, &mut client).await;

        // If no panic → success
    }

    #[tokio::test]
    async fn test_auth_invalid_user() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let (zkp, _) = setup_zkp();

        authenticate_user("nonexistent".into(), "pass".into(), &zkp, &mut client).await;

        // Should not panic
    }

    #[tokio::test]
    async fn test_auth_wrong_password() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        let (zkp, _) = setup_zkp();
        let username = format!("user_{}", Uuid::new_v4());

        register_user(username.clone(), "correct".into(), &zkp, &mut client).await;

        authenticate_user(username, "wrong".into(), &zkp, &mut client).await;

        // Should fail gracefully (no panic)
    }

    #[tokio::test]
    async fn test_validate_invalid_session() {
        let endpoint = spawn_test_server().await;
        let mut client = AuthClient::connect(endpoint).await.unwrap();

        validate_session("invalid_session".into(), &mut client).await;

        // Should not panic
    }
}