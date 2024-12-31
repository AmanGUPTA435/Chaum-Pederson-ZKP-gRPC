pub mod zkp_auth{
    include!("./zkp_auth.rs");
}
use std::{collections::HashMap, sync::Mutex};
use chaum_pederson_rust::ZKP;
use num_bigint::BigUint;
use tonic::{transport::Server, Request, Response, Result, Status};
use zkp_auth::{auth_server::{Auth, AuthServer}, AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};

#[derive(Debug, Default)]
pub struct AuthImpl{
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user: Mutex<HashMap<String,String>>
}

#[derive(Debug, Default)]
pub struct UserInfo {
    // registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    // authorization
    pub r1: BigUint,
    pub r2: BigUint,
    // verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
    
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing register: {:?}", request);
        let request = request.into_inner();
        let user_name = request.name;
        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        let mut user_info = UserInfo::default();
        user_info.user_name = user_name.clone();
        user_info.y1 = y1;
        user_info.y2 = y2;

        let _user_info = &mut self.user_info.lock().unwrap().insert(user_name, user_info);

        Ok(Response::new(RegisterResponse {}))
    }
    
    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing register: {:?}", request);
        let request = request.into_inner();
        let user_name = request.name;

        let r1 = BigUint::from_bytes_be(&request.r1);
        let r2 = BigUint::from_bytes_be(&request.r2);

        let mut user_info = self.user_info.lock().unwrap();
        if let Some(user) = user_info.get_mut(&user_name) {
            user.r1 = r1.clone();
            user.r2 = r2.clone();
            let (_,_,_,q) = ZKP::get_constants();
            let auth_id = ZKP::generate_random_string(12);
            let c = ZKP::generate_random_below(&q);
            user.c = c.clone();
            let mut auth_id_user = self.auth_id_to_user.lock().unwrap();
            auth_id_user.insert(auth_id.clone(), user_name);
            return Ok(Response::new(AuthenticationChallengeResponse {auth_id, c: c.to_bytes_be()}))
        } else {
            return Err(Status::not_found("user not found"));
        }

    }
    
    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing verification: {:?}", request);
        let request = request.into_inner();
        let auth_id = request.auth_id;

        let auth_id_map = self.auth_id_to_user.lock().unwrap();

        if let Some(user_name) = auth_id_map.get(&auth_id) {
            // let user_name = auth_id_map.get(auth_id_hash).unwrap();
            let user_info = &mut self.user_info.lock().unwrap();
            let user_info = user_info.get_mut(user_name).unwrap();

            let s = BigUint::from_bytes_be(&request.s);
            let (alpha, beta, p, q) = ZKP::get_constants();
            let zkp = ZKP {
                p,
                q,
                alpha,
                beta,
            };
            let verify = ZKP::verify(&zkp, &user_info.r1, &user_info.r2, &user_info.y1, &user_info.y2, &user_info.c, &s);
            if verify {
                let session_id = ZKP::generate_random_string(12);    
                user_info.session_id = session_id.clone();
                return Ok(Response::new(AuthenticationAnswerResponse {session_id}));
            } else {
                return Err(Status::new(tonic::Code::PermissionDenied, format!("Auth id: {} send a bad solution to the challenge", auth_id)))
            }
        //    user_info. 
        } else {
            return Err(Status::new(tonic::Code::NotFound, format!("Auth id {} not found", auth_id)));
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();
    println!("Running the server: {}", addr);

    let auth_impl = AuthImpl::default();
    Server::builder().add_service(AuthServer::new(auth_impl)).serve(addr.parse().expect("couldn't convert address")).await.unwrap();
}