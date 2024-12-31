use std::io::stdin;
use num_bigint::BigUint;
use tonic::Request;
use zkp_auth::{auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest};
use chaum_pederson_rust::ZKP;

pub mod zkp_auth{
    include!("./zkp_auth.rs");
}

#[tokio::main]
async fn main() {
    let mut buf = String::new();
    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP {
        p,
        q,
        alpha,
        beta,
    };

    let mut client = AuthClient::connect("http://127.0.0.1:50051").await.expect("couldn't connect to server");
    println!("yoooo m the client");
    println!("Please provide the username:");
    stdin().read_line(&mut buf).expect("Username not provided");
    let username = buf.trim().to_string();
    buf.clear();
    println!("Please provide the password:");
    stdin().read_line(&mut buf).expect("Password not provided");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();
    
    let y1 = zkp.exponentiate( &zkp.alpha, &password);
    let y2 = zkp.exponentiate( &zkp.beta, &password);
    let request = RegisterRequest {
        name: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    let response = client.register(request).await.expect("Could not register in server");
    println!("Response: {:?}", response);
    
    println!("Please provide the password:");
    stdin().read_line(&mut buf).expect("Password not provided");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let k = ZKP::generate_random_below(&zkp.q);
    let r1 = zkp.exponentiate( &zkp.alpha, &k);
    let r2 = zkp.exponentiate( &zkp.beta, &k);
    
    let request = AuthenticationChallengeRequest {
        name: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be()
    };
    
    let response = client.create_authentication_challenge(request).await.expect("Couldn't respond to the challenge").into_inner();
    println!("Authentication Challenge Response: {:?}", response);
    
    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);
    let s = zkp.solve(&k, &c, &password);
    
    let request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };
    
    let response = client.verify_authentication(request).await.expect("Could not verify in server");
    println!("Response: {:?}", response);
    

}