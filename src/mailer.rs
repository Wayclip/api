use crate::settings::Settings;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use std::fs;

#[derive(Clone)]
pub struct Mailer {
    config: Settings,
    mailer: SmtpTransport,
    from_address: String,
}

impl Mailer {
    pub fn new(config: &Settings) -> Self {
        let smtp_host = config.smtp_host.clone().expect("No host provided");
        let smtp_port = config.smtp_port.unwrap_or(587);
        let smtp_user = config.smtp_user.clone().expect("No user provided");
        let smtp_pass = config.smtp_password.clone().expect("No password provided");
        let from_address = config
            .smtp_from_address
            .clone()
            .expect("No address provided");

        let creds = Credentials::new(smtp_user, smtp_pass);

        let mailer = SmtpTransport::relay(&smtp_host)
            .expect("Failed to build SMTP transport")
            .port(smtp_port)
            .credentials(creds)
            .build();

        Self {
            config: config.clone(),
            mailer,
            from_address,
        }
    }

    fn read_and_populate_template(
        &self,
        template_name: &str,
        placeholders: &[(&str, &str)],
    ) -> String {
        let template_path = format!("assets/{template_name}.html");
        let mut template =
            fs::read_to_string(&template_path).expect("Should have been able to read the file");

        for (key, value) in placeholders {
            template = template.replace(&format!("{{{{{key}}}}}"), value);
        }
        template
    }

    pub fn send_verification_email(
        &self,
        to: &str,
        username: &str,
        token: &uuid::Uuid,
    ) -> Result<(), lettre::transport::smtp::Error> {
        let config = self.config.clone();
        let app_name = config.app_name;
        let redirect_uri = config.backend_url;
        let verification_link = format!("{redirect_uri}/auth/verify-email/{token}");

        let subject = format!("Welcome to {app_name}! Please Verify Your Email");
        let body_text = format!("Thank you for registering with {app_name}. Please click the button below to verify your email address:");
        let button_text = "Verify Email";

        let html_body = self.read_and_populate_template(
            "email",
            &[
                ("subject", subject.as_str()),
                ("username", username),
                ("body", body_text.as_str()),
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
        let config = self.config.clone();
        let app_name = config.app_name;
        let frontend_url = config.frontend_url;
        let reset_link = format!("{frontend_url}/reset-password?token={token}");

        let subject = format!("{app_name} Password Reset Request");
        let body_text =
            "You requested a password reset. Click the button below to reset your password:";
        let button_text = "Reset Password";

        let html_body = self.read_and_populate_template(
            "email",
            &[
                ("subject", subject.as_str()),
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

    pub fn send_new_login_email(
        &self,
        to: &str,
        username: &str,
        user_agent: &str,
    ) -> Result<(), lettre::transport::smtp::Error> {
        let config = self.config.clone();
        let app_name = config.app_name;
        let frontend_url = config.frontend_url;
        let security_link = format!("{frontend_url}/dash");

        let subject = format!("Security Alert: New Sign-in to Your {app_name} Account");
        let body_text = &format!(
        "We noticed a new sign-in to your account from a new device ({}). If this was you, you can safely ignore this email. If you don't recognize this activity, please secure your account immediately by reviewing your active sessions and changing your password.",
        user_agent
    );
        let button_text = "Review Account Security";

        let html_body = self.read_and_populate_template(
            "email",
            &[
                ("subject", subject.as_str()),
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
