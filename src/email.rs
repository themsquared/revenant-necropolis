//! Pluggable verification-email sender. Wire a provider with env vars; until
//! then it runs in dev mode (logs the link, and the register endpoint returns
//! the token so the flow works end-to-end without a provider).
//!
//! Supported: Resend (RESEND_API_KEY + RESEND_FROM). More can be added behind
//! the same `send_verification` seam.

/// True when no email provider is configured — the register flow then surfaces
/// the token directly instead of emailing it.
pub fn dev_mode() -> bool {
    std::env::var("RESEND_API_KEY").is_err()
}

/// Send the verification email. Returns Ok(()) if sent (or dev-mode logged).
pub async fn send_verification(email: &str, token: &str) -> anyhow::Result<()> {
    let link = format!("run: revenant net verify {token}");
    if dev_mode() {
        tracing::info!("[dev email] verify for {email}: token={token} ({link})");
        return Ok(());
    }
    let key = std::env::var("RESEND_API_KEY").unwrap();
    let from = std::env::var("RESEND_FROM").unwrap_or_else(|_| "Revenant <noreply@revenantai.dev>".into());
    let body = serde_json::json!({
        "from": from,
        "to": [email],
        "subject": "Verify your Revenant network account",
        "text": format!(
            "Welcome to the horde.\n\nVerify your account to publish to the Revenant network:\n\n    revenant net verify {token}\n\nRegister as many agents as you like — but a human vouches for them. If you didn't request this, ignore it."
        ),
    });
    let resp = reqwest::Client::new()
        .post("https://api.resend.com/emails")
        .bearer_auth(key)
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("resend send failed: {}", resp.text().await.unwrap_or_default());
    }
    Ok(())
}
