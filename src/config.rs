use std::time::Duration;

#[derive(Debug, Clone)]
pub struct FutureAuthConfig {
    /// FutureAuth server URL (e.g. "https://future-auth.com")
    pub api_url: String,
    /// Project secret key (vx_sec_...)
    pub secret_key: String,
    /// Project name (used in OTP messages)
    pub project_name: String,
    /// Session duration (default: 30 days)
    pub session_ttl: Duration,
    /// OTP code duration (default: 2 minutes)
    pub otp_ttl: Duration,
    /// OTP code length (default: 6)
    pub otp_length: usize,
    /// Cookie name for session token
    pub cookie_name: String,
}

impl Default for FutureAuthConfig {
    fn default() -> Self {
        Self {
            api_url: "https://future-auth.com".into(),
            secret_key: String::new(),
            project_name: String::new(),
            session_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            otp_ttl: Duration::from_secs(2 * 60),
            otp_length: 6,
            cookie_name: "futureauth_session".into(),
        }
    }
}
