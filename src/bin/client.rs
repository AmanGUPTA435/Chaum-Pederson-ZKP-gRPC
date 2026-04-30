#[tokio::main]
async fn main() {
    chaum_pederson_rust::client::run_client().await;
}