//! Print what the panel applet would show, without needing a panel.
#[tokio::main]
async fn main() {
    match locket_secret::client::status().await {
        Some(s) if !s.locked => {
            println!(
                "icon=channel-secure-symbolic    \"Unlocked · {} items\"",
                s.items
            )
        }
        Some(_) => println!("icon=channel-insecure-symbolic  \"Locked\""),
        None => println!("icon=dialog-password-symbolic   \"locketd is not running\""),
    }
}
