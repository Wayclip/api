use crate::log;
use crate::settings::Settings;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ssh2::{OpenFlags, OpenType, Session as Ssh2Session};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::task;
use uuid::Uuid;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn upload(&self, file_name: &str, data: Vec<u8>) -> Result<String>;
    async fn delete(&self, storage_path: &str) -> Result<()>;
    async fn download(&self, storage_path: &str) -> Result<Vec<u8>>;
}

pub struct LocalStorage {
    storage_path: PathBuf,
}

impl LocalStorage {
    pub fn new(settings: &Settings) -> Self {
        let path = settings
            .local_storage_path
            .clone()
            .expect("LOCAL_STORAGE_PATH is required for LOCAL storage type");
        Self {
            storage_path: PathBuf::from(path),
        }
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn upload(&self, file_name: &str, data: Vec<u8>) -> Result<String> {
        log!([DEBUG] => "LOCAL: Uploading file '{}'", file_name);

        fs::create_dir_all(&self.storage_path).await?;

        let extension = Path::new(file_name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");
        let unique_filename = format!("{}.{}", Uuid::new_v4(), extension);

        let file_path = self.storage_path.join(&unique_filename);
        fs::write(&file_path, data).await?;
        log!([DEBUG] => "LOCAL: File saved to '{}'", file_path.display());

        Ok(unique_filename)
    }

    async fn delete(&self, storage_path: &str) -> Result<()> {
        log!([CLEANUP] => "LOCAL: Deleting file '{}'", storage_path);

        let file_path = self.storage_path.join(storage_path);

        if !file_path.starts_with(&self.storage_path) {
            return Err(anyhow!(
                "Invalid storage path for deletion: {}",
                storage_path
            ));
        }

        fs::remove_file(&file_path).await?;
        log!([CLEANUP] => "LOCAL: Deletion successful.");
        Ok(())
    }

    async fn download(&self, storage_path: &str) -> Result<Vec<u8>> {
        log!([DEBUG] => "LOCAL: Downloading file '{}'", storage_path);

        let file_path = self.storage_path.join(storage_path);

        if !file_path.starts_with(&self.storage_path) {
            return Err(anyhow!(
                "Invalid storage path for download: {}",
                storage_path
            ));
        }

        let data = fs::read(&file_path).await?;
        log!([DEBUG] => "LOCAL: Successfully read {} bytes.", data.len());
        Ok(data)
    }
}

pub struct SftpStorage {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    remote_path: String,
    public_url: String,
    server_public_key: Option<String>,
}

impl SftpStorage {
    pub fn new(settings: &Settings) -> Self {
        Self {
            host: settings.sftp_host.clone().expect("SFTP_HOST is required"),
            port: settings.sftp_port.unwrap_or(22),
            user: settings.sftp_user.clone().expect("SFTP_USER is required"),
            password: settings.sftp_password.clone(),
            remote_path: settings
                .sftp_remote_path
                .clone()
                .expect("SFTP_REMOTE_PATH is required"),
            public_url: settings
                .sftp_public_url
                .clone()
                .expect("SFTP_PUBLIC_URL is required"),
            server_public_key: settings.sftp_server_public_key.clone(),
        }
    }

    async fn with_ssh2<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Ssh2Session) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let host = self.host.clone();
        let port = self.port;
        let user = self.user.clone();
        let password = self.password.clone();

        task::spawn_blocking(move || -> Result<T> {
            let addr = format!("{}:{}", host, port);
            let tcp = std::net::TcpStream::connect(addr)?;
            let mut sess = Ssh2Session::new()?;
            sess.set_blocking(true);
            sess.set_tcp_stream(tcp);
            sess.handshake()?;

            if let Some(pw) = password {
                sess.userauth_password(user.as_str(), &pw)?;
            } else {
                return Err(anyhow!("SFTP password authentication is required"));
            }

            if !sess.authenticated() {
                return Err(anyhow!("SFTP authentication failed."));
            }

            let result = f(&sess)?;
            Ok(result)
        })
        .await?
    }

    async fn upload_to_remote(&self, remote_path: &str, data: &[u8]) -> Result<()> {
        let remote_path = remote_path.to_owned();
        let data = data.to_owned();

        self.with_ssh2(move |sess| {
            let sftp = sess.sftp()?;
            if let Some(parent) = Path::new(&remote_path).parent() {
                let _ = sftp.mkdir(parent, 0o755);
            }
            let mut remote_file = sftp.open_mode(
                Path::new(&remote_path),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                0o644,
                OpenType::File,
            )?;
            remote_file.write_all(&data)?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow!(e))
    }

    async fn download_from_remote(&self, remote_path: &str) -> Result<Vec<u8>> {
        let remote_path = remote_path.to_owned();
        self.with_ssh2(move |sess| {
            let sftp = sess.sftp()?;
            let mut remote_file = sftp.open(Path::new(&remote_path))?;
            let mut buf = Vec::new();
            remote_file.read_to_end(&mut buf)?;
            Ok(buf)
        })
        .await
        .map_err(|e| anyhow!(e))
    }

    async fn delete_remote_file(&self, remote_path: &str) -> Result<()> {
        let remote_path = remote_path.to_owned();
        self.with_ssh2(move |sess| {
            let sftp = sess.sftp()?;
            match sftp.unlink(Path::new(&remote_path)) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!(e)),
            }
        })
        .await
        .map_err(|e| anyhow!(e))
    }
}

#[async_trait]
impl Storage for SftpStorage {
    async fn upload(&self, file_name: &str, data: Vec<u8>) -> Result<String> {
        log!([DEBUG] => "SFTP (ssh2): Uploading file '{}'", file_name);

        let remote_dir = self.remote_path.trim_end_matches('/');
        let extension = Path::new(file_name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("mp4");
        let unique_filename = format!("{}.{}", Uuid::new_v4(), extension);
        let remote_file_path = format!("{}/{}", remote_dir, unique_filename);

        self.upload_to_remote(&remote_file_path, &data).await?;

        Ok(unique_filename)
    }

    async fn delete(&self, storage_path: &str) -> Result<()> {
        log!([CLEANUP] => "SFTP (ssh2): Deleting file from filename '{}'", storage_path);
        let remote_dir = self.remote_path.trim_end_matches('/');
        let remote_file_path = format!("{}/{}", remote_dir, storage_path);

        self.delete_remote_file(&remote_file_path).await?;
        log!([CLEANUP] => "SFTP (ssh2): Deletion successful.");
        Ok(())
    }

    async fn download(&self, storage_path: &str) -> Result<Vec<u8>> {
        log!([DEBUG] => "SFTP (ssh2): Downloading file from filename '{}'", storage_path);
        let remote_dir = self.remote_path.trim_end_matches('/');
        let remote_file_path = format!("{}/{}", remote_dir, storage_path);

        let data = self.download_from_remote(&remote_file_path).await?;
        log!([DEBUG] => "SFTP (ssh2): Successfully read {} bytes.", data.len());
        Ok(data)
    }
}
