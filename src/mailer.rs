use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use std::env;
use std::fs;

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

    fn read_and_populate_template(
        &self,
        template_name: &str,
        placeholders: &[(&str, &str)],
    ) -> String {
        let template_path = format!("assets/{}.html", template_name);
        let mut template =
            fs::read_to_string(&template_path).expect("Should have been able to read the file");

        for (key, value) in placeholders {
            template = template.replace(&format!("{{{{{}}}}}", key), value);
        }
        template
    }

    pub fn send_verification_email(
        &self,
        to: &str,
        username: &str,
        token: &uuid::Uuid,
    ) -> Result<(), lettre::transport::smtp::Error> {
        let redirect_url = env::var("REDIRECT_URL").expect("REDIRECT_URL must be set");
        let verification_link = format!("{redirect_url}/auth/verify-email/{token}");

        let subject = "Welcome to Wayclip! Please Verify Your Email";
        let body_text = "Thank you for registering with Wayclip. Please click the button below to verify your email address:";
        let button_text = "Verify Email";

        let html_body = self.read_and_populate_template(
            "email",
            &[
                ("subject", subject),
                ("username", username),
                ("body", body_text),
                ("link", &verification_link),
                ("button_text", button_text),
            ],
        );

        let email = Message::builder()
            .from(self.from_address.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body)
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
        let reset_link = format!("{frontend_url}/reset-password?token={token}");

        let subject = "Wayclip Password Reset Request";
        let body_text =
            "You requested a password reset. Click the button below to reset your password:";
        let button_text = "Reset Password";

        let html_body = self.read_and_populate_template(
            "email",
            &[
                ("subject", subject),
                ("username", username),
                ("body", body_text),
                ("link", &reset_link),
                ("button_text", button_text),
            ],
        );

        let email = Message::builder()
            .from(self.from_address.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body)
            .unwrap();

        self.mailer.send(&email)?;

        Ok(())
    }

    pub fn send_unrecognized_device_email(
        &self,
        to: &str,
        username: &str,
        ip_address: &str,
    ) -> Result<(), lettre::transport::smtp::Error> {
        let frontend_url =
            env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let security_link = format!("{frontend_url}/dash");

        let subject = "Security Alert: New Sign-in to Your Wayclip Account";
        let body_text = &format!(
            "We noticed a new sign-in to your account from an unrecognized device (IP: {}). If this was you, you can safely ignore this email. If you don't recognize this activity, please secure your account immediately.",
            ip_address
        );
        let button_text = "Review Account Security";

        let html_body = self.read_and_populate_template(
            "email",
            &[
                ("subject", subject),
                ("username", username),
                ("body", body_text),
                ("link", &security_link),
                ("button_text", button_text),
            ],
        );

        let email = Message::builder()
            .from(self.from_address.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body)
            .unwrap();

        self.mailer.send(&email)?;

        Ok(())
    }
}
