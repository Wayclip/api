use crate::settings::Settings;
use anyhow::Result;
use async_trait::async_trait;
use ssh2::{Sftp, Session};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;
use wayclip_core::log;

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
        if !self.storage_path.exists() {
            fs::create_dir_all(&self.storage_path).await?;
        }

        let extension = Path::new(file_name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("mp4");
        let unique_filename = format!("{}.{}", Uuid::new_v4(), extension);
        let dest_path = self.storage_path.join(&unique_filename);
        log!([DEBUG] => "LOCAL: Writing file to '{}'", dest_path.display());

        fs::write(&dest_path, data).await?;

        Ok(unique_filename)
    }

    async fn delete(&self, storage_path: &str) -> Result<()> {
        log!([CLEANUP] => "LOCAL: Deleting file '{}'", storage_path);
        let file_path = self.storage_path.join(storage_path);
        if file_path.exists() {
            fs::remove_file(&file_path).await?;
            log!([DEBUG] => "LOCAL: Successfully deleted '{}'", file_path.display());
        } else {
            log!([DEBUG] => "LOCAL: File '{}' not found, skipping deletion.", file_path.display());
        }
        Ok(())
    }

    async fn download(&self, storage_path: &str) -> Result<Vec<u8>> {
        log!([DEBUG] => "LOCAL: Reading file '{}'", storage_path);
        let file_path = self.storage_path.join(storage_path);
        let data = fs::read(&file_path).await?;
        log!([DEBUG] => "LOCAL: Successfully read {} bytes from '{}'", data.len(), file_path.display());
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
        }
    }

    fn get_sftp_client(&self) -> Result<Sftp> {
        log!([DEBUG] => "SFTP (blocking): Connecting to {}:{}", self.host, self.port);
        let tcp = TcpStream::connect(format!("{}:{}", self.host, self.port))?;
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        if let Some(pass) = self.password.as_deref() {
            sess.userauth_password(&self.user, pass)?;
        } else {
            return Err(anyhow::anyhow!("SFTP password authentication is required"));
        }

        log!([DEBUG] => "SFTP (blocking): Authentication successful.");
        let sftp = sess.sftp()?;
        Ok(sftp)
    }

    fn filename_from_storage_path<'a>(&self, storage_path: &'a str) -> Result<&'a str> {
        Path::new(storage_path)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Could not parse filename from SFTP URL: {}", storage_path))
    }
}

#[async_trait]
impl Storage for SftpStorage {
    async fn upload(&self, file_name: &str, data: Vec<u8>) -> Result<String> {
        log!([DEBUG] => "SFTP: Uploading file '{}' to {}", file_name, self.host);

        let me = self.clone();
        let owned_file_name = file_name.to_string();

        tokio::task::spawn_blocking(move || -> Result<String> {
            let sftp = me.get_sftp_client()?;
            let remote_dir = Path::new(&me.remote_path);

            sftp.mkdir(remote_dir, 0o755).ok();

            let extension = Path::new(&owned_file_name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("mp4");
            let unique_filename = format!("{}.{}", Uuid::new_v4(), extension);
            let remote_file_path = remote_dir.join(&unique_filename);

            log!([DEBUG] => "SFTP (blocking): Writing to remote path: {}", remote_file_path.display());
            let mut remote_file = sftp.create(remote_file_path.as_path())?;
            remote_file.write_all(&data)?;
            log!([DEBUG] => "SFTP: Upload successful.");

            let public_url = format!("{}/{}", me.public_url, unique_filename);
            Ok(public_url)
        })
        .await?
    }

    async fn delete(&self, storage_path: &str) -> Result<()> {
        log!([CLEANUP] => "SFTP: Deleting file from URL '{}'", storage_path);
        let file_name = self.filename_from_storage_path(storage_path)?;

        let me = self.clone();
        let file_name_owned = file_name.to_string();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let sftp = me.get_sftp_client()?;
            let remote_file_path = Path::new(&me.remote_path).join(&file_name_owned);
            log!([DEBUG] => "SFTP (blocking): Unlinking remote file: {}", remote_file_path.display());
            sftp.unlink(&remote_file_path)?;
            Ok(())
        })
        .await??;
        log!([CLEANUP] => "SFTP: Deletion successful.");
        Ok(())
    }

    async fn download(&self, storage_path: &str) -> Result<Vec<u8>> {
        log!([DEBUG] => "SFTP: Downloading file from URL '{}'", storage_path);
        let file_name = self.filename_from_storage_path(storage_path)?;

        let me = self.clone();
        let file_name_owned = file_name.to_string();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let sftp = me.get_sftp_client()?;
            let remote_file_path = Path::new(&me.remote_path).join(&file_name_owned);

            log!([DEBUG] => "SFTP (blocking): Opening remote file for reading: {}", remote_file_path.display());
            let mut remote_file = sftp.open(remote_file_path.as_path())?;
            
            let mut buffer = Vec::new();
            remote_file.read_to_end(&mut buffer)?;
            
            log!([DEBUG] => "SFTP (blocking): Successfully read {} bytes.", buffer.len());
            Ok(buffer)
        })
        .await?
    }
}

impl Clone for SftpStorage {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            password: self.password.clone(),
            remote_path: self.remote_path.clone(),
            public_url: self.public_url.clone(),
        }
    }
}
