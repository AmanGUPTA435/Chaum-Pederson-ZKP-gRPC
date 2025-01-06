use std::io::stdin; 
use num_bigint::BigUint; // Import BigUint for handling large integers.
use tonic::Request; // Import Tonic's Request for making gRPC calls.
use zkp_auth::{auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest};
use chaum_pederson_rust::ZKP; // Import ZKP struct and related methods from Chaum-Pederson library.

pub mod zkp_auth {
    include!("./zkp_auth.rs"); // Include generated gRPC code for zkp_auth module.
}

#[tokio::main] 
async fn main() {
    let mut buf = String::new(); // Buffer for user input.
    
    // Retrieve constants like alpha, beta, p, and q used for Zero-Knowledge Proofs.
    let (alpha, beta, p, q) = ZKP::get_constants();
    
    // Initialize the ZKP struct with constants.
    let zkp = ZKP {
        p,
        q,
        alpha,
        beta,
    };

    // Connect to the authentication server via gRPC.
    let mut client = AuthClient::connect("http://127.0.0.1:50051")
        .await
        .expect("Couldn't connect to server");

    println!("yoooo m the client"); // Debug message.
    
    // Step 1: Register the user.
    println!("Please provide the username:");
    stdin().read_line(&mut buf).expect("Username not provided");
    let username = buf.trim().to_string(); // Get and trim the username input.
    buf.clear(); // Clear buffer for reuse.

    println!("Please provide the password:");
    stdin().read_line(&mut buf).expect("Password not provided");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes()); // Convert password to BigUint.
    buf.clear();

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
    let response = client
        .register(request)
        .await
        .expect("Could not register in server");
    println!("Response: {:?}", response);

    // Step 2: Authentication challenge-response.
    println!("Please provide the password:");
    stdin().read_line(&mut buf).expect("Password not provided");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes()); // Convert password to BigUint.
    buf.clear();

    // Generate a random challenge value k < q.
    let k = ZKP::generate_random_below(&zkp.q);

    // Compute r1 = alpha^k mod p and r2 = beta^k mod p as part of the authentication challenge.
    let r1 = zkp.exponentiate(&zkp.alpha, &k);
    let r2 = zkp.exponentiate(&zkp.beta, &k);

    // Create an authentication challenge request.
    let request = AuthenticationChallengeRequest {
        name: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    // Send the challenge request to the server and handle response.
    let response = client
        .create_authentication_challenge(request)
        .await
        .expect("Couldn't respond to the challenge")
        .into_inner();
    println!("Authentication Challenge Response: {:?}", response);

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

    // Send the answer to the server for verification and handle response.
    let response = client
        .verify_authentication(request)
        .await
        .expect("Could not verify in server");
    println!("Response: {:?}", response); // Print server's verification result.
}
