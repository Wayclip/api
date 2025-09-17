use crate::log;
use crate::settings::Settings;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{Stream, StreamExt};
use r2d2::ManageConnection;
use ssh2::{OpenFlags, OpenType, Session};
use std::error::Error as StdError;
use std::fmt;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task;
use tokio_util::codec::{BytesCodec, FramedRead};
use uuid::Uuid;

type ByteStream = Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send + Unpin>;

pub struct StreamResponse {
    pub stream: ByteStream,
    pub total_size: u64,
    pub content_range: String,
    pub content_length: u64,
}

#[derive(Debug)]
pub enum Ssh2ManagerError {
    Io(std::io::Error),
    Ssh(ssh2::Error),
    Auth(String),
}

impl fmt::Display for Ssh2ManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ssh2ManagerError::Io(e) => write!(f, "IO error: {}", e),
            Ssh2ManagerError::Ssh(e) => write!(f, "SSH error: {}", e),
            Ssh2ManagerError::Auth(msg) => write!(f, "Authentication error: {}", msg),
        }
    }
}

impl StdError for Ssh2ManagerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Ssh2ManagerError::Io(e) => Some(e),
            Ssh2ManagerError::Ssh(e) => Some(e),
            Ssh2ManagerError::Auth(_) => None,
        }
    }
}

impl From<std::io::Error> for Ssh2ManagerError {
    fn from(err: std::io::Error) -> Self {
        Ssh2ManagerError::Io(err)
    }
}

impl From<ssh2::Error> for Ssh2ManagerError {
    fn from(err: ssh2::Error) -> Self {
        Ssh2ManagerError::Ssh(err)
    }
}

#[derive(Debug, Clone)]
pub struct Ssh2ConnectionManager {
    host: String,
    port: u16,
    user: String,
    pass: String,
}

impl ManageConnection for Ssh2ConnectionManager {
    type Connection = Session;
    type Error = Ssh2ManagerError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let addr = format!("{}:{}", self.host, self.port);
        let tcp = TcpStream::connect(&addr)?;
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;
        sess.userauth_password(&self.user, &self.pass)?;

        if !sess.authenticated() {
            return Err(Ssh2ManagerError::Auth(format!(
                "SFTP authentication failed for user '{}'",
                self.user
            )));
        }
        Ok(sess)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.keepalive_send()?;
        Ok(())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.keepalive_send().is_err()
    }
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn upload(&self, file_name: &str, stream: ByteStream) -> Result<(String, i64)>;
    async fn delete(&self, storage_path: &str) -> Result<()>;
    async fn download_stream(
        &self,
        storage_path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<StreamResponse>;
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
    async fn upload(&self, file_name: &str, mut stream: ByteStream) -> Result<(String, i64)> {
        log!([DEBUG] => "LOCAL: Uploading file '{}'", file_name);
        tokio::fs::create_dir_all(&self.storage_path).await?;
        let extension = Path::new(file_name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");
        let unique_filename = format!("{}.{}", Uuid::new_v4(), extension);
        let file_path = self.storage_path.join(&unique_filename);
        let mut file = File::create(&file_path).await?;
        let mut total_bytes = 0;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| anyhow!("Upload stream error: {}", e))?;
            file.write_all(&chunk).await?;
            total_bytes += chunk.len() as i64;
        }
        log!([DEBUG] => "LOCAL: Upload of {} bytes to '{}' complete.", total_bytes, unique_filename);
        Ok((unique_filename, total_bytes))
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
        tokio::fs::remove_file(&file_path).await?;
        Ok(())
    }

    async fn download_stream(
        &self,
        storage_path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<StreamResponse> {
        let file_path = self.storage_path.join(storage_path);
        let mut file = File::open(file_path).await?;
        let total_size = file.metadata().await?.len();

        let (start, length) = match range {
            Some((start, length)) => (start, length.min(total_size - start)),
            None => (0, total_size),
        };

        let end = start + length - 1;

        file.seek(SeekFrom::Start(start)).await?;
        let stream = FramedRead::new(file.take(length), BytesCodec::new())
            .map(|result| result.map(|bytes_mut| bytes_mut.freeze()));

        let content_range = format!("bytes {}-{}/{}", start, end, total_size);

        Ok(StreamResponse {
            stream: Box::new(stream),
            total_size,
            content_range,
            content_length: length,
        })
    }
}

pub struct SftpStorage {
    pool: r2d2::Pool<Ssh2ConnectionManager>,
    remote_path: String,
}

impl SftpStorage {
    pub fn new(settings: &Settings) -> Result<Self> {
        let host = settings.sftp_host.clone().expect("SFTP_HOST is required");
        let port = settings.sftp_port.unwrap_or(22);
        let user = settings.sftp_user.clone().expect("SFTP_USER is required");
        let pass = settings
            .sftp_password
            .clone()
            .expect("SFTP_PASSWORD is required");

        log!([DEBUG] => "Creating SFTP connection manager for host: {}:{}", host, port);

        let manager = Ssh2ConnectionManager {
            host,
            port,
            user,
            pass,
        };

        let pool = r2d2::Pool::builder()
            .max_size(25)
            .min_idle(Some(5))
            .connection_timeout(std::time::Duration::from_secs(10))
            .build(manager)
            .map_err(|e| anyhow!("Failed to build SFTP connection pool: {}", e))?;

        log!([DEBUG] => "SFTP connection pool created successfully.");

        Ok(Self {
            pool,
            remote_path: settings
                .sftp_remote_path
                .clone()
                .expect("SFTP_REMOTE_PATH is required"),
        })
    }
}

#[async_trait]
impl Storage for SftpStorage {
    async fn upload(&self, file_name: &str, mut stream: ByteStream) -> Result<(String, i64)> {
        let remote_dir = self.remote_path.trim_end_matches('/').to_string();
        let extension = Path::new(file_name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("mp4");
        let unique_filename = format!("{}.{}", Uuid::new_v4(), extension);
        let remote_file_path = format!("{}/{}", remote_dir, unique_filename);

        let pool = self.pool.clone();

        let uploader = task::spawn_blocking(move || -> Result<i64> {
            log!([DEBUG] => "SFTP POOL: Getting connection for upload...");
            let conn = pool.get()?;
            let sftp = conn.sftp()?;

            if let Some(parent) = Path::new(&remote_file_path).parent() {
                let _ = sftp.mkdir(parent, 0o755);
            }

            let mut remote_file = sftp.open_mode(
                Path::new(&remote_file_path),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                0o644,
                OpenType::File,
            )?;

            let mut total_bytes = 0;
            let rt = tokio::runtime::Handle::current();
            while let Some(chunk_result) = rt.block_on(stream.next()) {
                match chunk_result {
                    Ok(chunk) => {
                        remote_file.write_all(&chunk)?;
                        total_bytes += chunk.len() as i64;
                    }
                    Err(e) => return Err(e.into()),
                }
            }

            log!([DEBUG] => "SFTP POOL: Upload of {} bytes to '{}' complete.", total_bytes, remote_file_path);
            Ok(total_bytes)
        });

        let total_bytes = uploader.await??;
        Ok((unique_filename, total_bytes))
    }

    async fn delete(&self, storage_path: &str) -> Result<()> {
        let remote_dir = self.remote_path.trim_end_matches('/').to_string();
        let remote_file_path = format!("{}/{}", remote_dir, storage_path);

        let pool = self.pool.clone();
        task::spawn_blocking(move || -> Result<()> {
            log!([CLEANUP] => "SFTP POOL: Getting connection for delete: {}", remote_file_path);
            let conn = pool.get()?;
            let sftp = conn.sftp()?;
            sftp.unlink(Path::new(&remote_file_path))?;
            log!([CLEANUP] => "SFTP POOL: Deletion successful.");
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn download_stream(
        &self,
        storage_path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<StreamResponse> {
        let remote_dir = self.remote_path.trim_end_matches('/').to_string();
        let remote_file_path_str = format!("{}/{}", remote_dir, storage_path);

        let pool = self.pool.clone();
        let remote_file_path_for_stat = remote_file_path_str.clone();

        let total_size = task::spawn_blocking(move || -> Result<u64> {
            let conn = pool.get()?;
            let sftp = conn.sftp()?;
            let stat = sftp.stat(Path::new(&remote_file_path_for_stat))?;
            Ok(stat.size.unwrap_or(0))
        })
        .await??;

        if total_size == 0 {
            return Err(anyhow!("File size is 0 or could not be determined."));
        }

        let (start, read_len) = match range {
            Some((start, length)) => (start, length.min(total_size - start)),
            None => (0, total_size),
        };
        let end = start + read_len - 1;

        let content_range = format!("bytes {}-{}/{}", start, end, total_size);

        let pool = self.pool.clone();
        let (tx, rx) = mpsc::channel(4);

        task::spawn_blocking(move || {
            let result: Result<()> = (|| {
                let conn = pool.get()?;
                let sftp = conn.sftp()?;
                let mut remote_file = sftp.open(Path::new(&remote_file_path_str))?;
                remote_file.seek(SeekFrom::Start(start))?;

                let mut buffer = vec![0; 1024 * 512];
                let mut bytes_left_to_read = read_len;

                while bytes_left_to_read > 0 {
                    let bytes_to_read = buffer.len().min(bytes_left_to_read as usize);
                    match remote_file.read(&mut buffer[..bytes_to_read]) {
                        Ok(0) => break,
                        Ok(n) => {
                            if tx
                                .blocking_send(Ok(Bytes::copy_from_slice(&buffer[..n])))
                                .is_err()
                            {
                                break;
                            }
                            bytes_left_to_read -= n as u64;
                        }
                        Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(())
            })();

            if let Err(e) = result {
                log!([DEBUG] => "ERROR: SFTP Stream failed: {}", e);
                let _ = tx.blocking_send(Err(std::io::Error::new(ErrorKind::Other, e.to_string())));
            }
        });

        Ok(StreamResponse {
            stream: Box::new(tokio_stream::wrappers::ReceiverStream::new(rx)),
            total_size,
            content_range,
            content_length: read_len,
        })
    }
}
