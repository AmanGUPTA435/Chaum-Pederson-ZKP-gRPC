#[tokio::main]
async fn main() {
    chaum_pederson_rust::server::run_server().await;
}