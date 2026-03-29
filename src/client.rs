use reqwest::Client;
use serde::Serialize;

use crate::config::FutureAuthConfig;
use crate::error::{Result, FutureAuthError};
use crate::models::OtpChannel;

#[derive(Serialize)]
struct SendOtpRequest<'a> {
    channel: OtpChannel,
    destination: &'a str,
    code: &'a str,
    project_name: &'a str,
}

pub async fn send_otp(
    http: &Client,
    config: &FutureAuthConfig,
    channel: OtpChannel,
    destination: &str,
    code: &str,
) -> Result<()> {
    let url = format!("{}/api/v1/otp/send", config.api_url);

    let resp = http
        .post(&url)
        .bearer_auth(&config.secret_key)
        .json(&SendOtpRequest {
            channel,
            destination,
            code,
            project_name: &config.project_name,
        })
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(FutureAuthError::OtpDeliveryFailed(body));
    }

    Ok(())
}
