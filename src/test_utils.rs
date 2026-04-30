use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::Arc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use crate::zkp_auth::auth_server::AuthServer;
use crate::server::{AuthImpl};
use crate::ZKP;
use num_bigint::BigUint;

pub async fn spawn_test_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();

    let addr = listener.local_addr().unwrap();

    dotenvy::from_filename(".env.test").ok();
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = PgPool::connect(&db_url).await.unwrap();

    let auth_impl = AuthImpl {
        db: db_pool,
        session_info: DashMap::new(),
        rate_limit_info: DashMap::new(),
    };

    let server = Arc::new(auth_impl);

    tokio::spawn(async move {
        Server::builder()
            .add_service(AuthServer::new(server))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    format!("http://{}", addr)
}

pub fn setup_zkp() -> (ZKP, BigUint) {
    let (alpha, beta, p, q) = ZKP::get_constants();

    let zkp = ZKP { p, q, alpha, beta };

    let password = ZKP::generate_random_below(&zkp.q);

    (zkp, password)
}