use tokio::net::TcpListener;
use veyl_relay_server::serve;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    if std::env::var("ALLOWED_ORIGINS").is_err() {
        eprintln!("ALLOWED_ORIGINS is unset; cross-origin browser requests are disabled.");
    }
    serve(listener).await
}
