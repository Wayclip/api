use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use std::env;

#[derive(Clone)]
pub struct Mailer {
    mailer: SmtpTransport,
    from_address: String,
}

impl Mailer {
    pub fn new() -> Self {
        let smtp_host = env::var("SMTP_HOST").expect("SMTP_HOST must be set");
        let smtp_user = env::var("SMTP_USER").expect("SMTP_USER must be set");
        let smtp_pass = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
        let from_address = env::var("SMTP_FROM_ADDRESS").expect("SMTP_FROM_ADDRESS must be set");

        let creds = Credentials::new(smtp_user, smtp_pass);

        let mailer = SmtpTransport::relay(&smtp_host)
            .unwrap()
            .credentials(creds)
            .build();

        Self {
            mailer,
            from_address,
        }
    }

    pub fn send_verification_email(
        &self,
        to: &str,
        username: &str,
        token: &uuid::Uuid,
    ) -> Result<(), lettre::transport::smtp::Error> {
        let redirect_url = env::var("REDIRECT_URL").expect("REDIRECT_URL must be set");
        let verification_link = format!("{}/auth/verify-email/{}", redirect_url, token);

        let email = Message::builder()
            .from(self.from_address.parse().unwrap())
            .to(to.parse().unwrap())
            .subject("Welcome to Wayclip! Please Verify Your Email")
            .body(format!(
                "Hello {},\n\nThank you for registering with Wayclip. Please click the link below to verify your email address:\n\n{}\n\nThis link will expire in 1 hour.\n\nThanks,\nThe Wayclip Team",
                username, verification_link
            ))
            .unwrap();

        self.mailer.send(&email)?;

        Ok(())
    }

    pub fn send_password_reset_email(
        &self,
        to: &str,
        username: &str,
        token: &uuid::Uuid,
    ) -> Result<(), lettre::transport::smtp::Error> {
        let frontend_url =
            env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let reset_link = format!("{}/reset-password?token={}", frontend_url, token);

        let email = Message::builder()
            .from(self.from_address.parse().unwrap())
            .to(to.parse().unwrap())
            .subject("Wayclip Password Reset Request")
            .body(format!(
                "Hello {},\n\nYou requested a password reset. Click the link below to reset your password:\n\n{}\n\nThis link will expire in 1 hour. If you did not request a password reset, please ignore this email.\n\nThanks,\nThe Wayclip Team",
                username, reset_link
            ))
            .unwrap();

        self.mailer.send(&email)?;

        Ok(())
    }
}
