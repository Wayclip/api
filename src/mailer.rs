use crate::settings::Settings;
use lettre::message::MultiPart;
use lettre::message::SinglePart;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
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
        let smtp_host = config
            .smtp_host
            .as_ref()
            .map(|s| s.trim())
            .expect("No host provided");
        let smtp_port = config.smtp_port.unwrap_or(587);
        let smtp_user = config
            .smtp_user
            .as_ref()
            .map(|s| s.trim())
            .expect("No user provided");
        let smtp_pass = config
            .smtp_password
            .as_ref()
            .map(|s| s.trim())
            .expect("No password provided");
        let from_address = config
            .smtp_from_address
            .as_ref()
            .map(|s| s.trim())
            .expect("No address provided");
        let connect_host = config.smtp_connect_host.as_deref().unwrap_or(smtp_host);
        let creds = Credentials::new(smtp_user.to_string(), smtp_pass.to_string());
        let tls = TlsParameters::new(smtp_host.to_string()).expect("TLS params");

        let mailer = SmtpTransport::builder_dangerous(connect_host)
            .port(smtp_port)
            .tls(Tls::Required(tls))
            .credentials(creds)
            .build();

        Self {
            config: config.clone(),
            mailer,
            from_address: from_address.to_string(),
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
            .singlepart(SinglePart::html(html_body))
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
            .singlepart(SinglePart::html(html_body))
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
        let app_name = config.app_name.trim();
        let frontend_url = config.frontend_url.trim();
        let security_link = format!("{frontend_url}/dash");

        let clean_user_agent = user_agent
            .replace(['\r', '\n'], "")
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>();

        let subject = format!("Security Alert: New Sign-in to Your {app_name} Account");

        let body_text = format!(
        "We noticed a new sign-in to your account from a new device ({}). If this was you, you can safely ignore this email.",
        clean_user_agent
    );

        let button_text = "Review Account Security";

        let html_body = self.read_and_populate_template(
            "email",
            &[
                ("subject", subject.as_str()),
                ("username", username),
                ("body", &body_text),
                ("link", &security_link),
                ("button_text", button_text),
            ],
        );

        println!("DEBUG: HTML Body length: {}", html_body.len());
        let email = Message::builder()
            .from(self.from_address.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject.clone())
            .multipart(MultiPart::alternative_plain_html(
                body_text.clone(), // plain text
                html_body.clone(), // html
            ))
            .unwrap();

        self.mailer.send(&email)?;

        Ok(())
    }
}
