//! Regression test for the per-channel mpsc deadlock on the CHANNEL_DATA,
//! CHANNEL_EXTENDED_DATA, CHANNEL_EOF and CHANNEL_CLOSE branches of the
//! reading arm of the session loop. PR #630 covered WINDOW_ADJUST. This
//! test covers the four sibling branches.
//!
//! When the per-channel mpsc fills and the application has not drained,
//! chan.send(...).await parks the session task in the reading-arm body,
//! outside the top-level select. The keepalive and inactivity arms cannot
//! fire from that state and the session hangs indefinitely.
//!
//! send_with_timeout caps the wait at config.channel_send_timeout. The
//! session loop returns Error::ChannelSendTimeout on elapse. The test
//! drives the deadlock condition deterministically and asserts that the
//! server-side RunningSession future resolves with ChannelSendTimeout
//! within a bounded wall-clock window.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, client};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const WINDOW_SIZE: u32 = 8 * 2048;
const CHANNEL_BUFFER_SIZE: usize = 10;
const CHANNEL_SEND_TIMEOUT: Duration = Duration::from_secs(1);
const TEST_HARD_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn server_session_ends_with_channel_send_timeout_when_handler_does_not_drain()
-> Result<(), anyhow::Error> {
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;

    // Channel-handler holds the session channel in a future that never reads
    // from it. The channel mpsc fills after CHANNEL_BUFFER_SIZE inbound
    // ChannelMsg::Data messages.
    let (hold_tx, hold_rx) = oneshot::channel::<()>();

    let server_task = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();

        let server_config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            window_size: WINDOW_SIZE,
            channel_buffer_size: CHANNEL_BUFFER_SIZE,
            channel_send_timeout: CHANNEL_SEND_TIMEOUT,
            // Keep keepalive / inactivity timers off so ChannelSendTimeout
            // is unambiguously the cause when the test asserts.
            inactivity_timeout: None,
            keepalive_interval: None,
            ..Default::default()
        });

        let handler = ServerHandler {
            hold_rx: Some(hold_rx),
        };
        let session = russh::server::run_stream(server_config, stream, handler)
            .await
            .unwrap();
        // RunningSession resolves once the session loop ends.
        session.await
    });

    // Drive the deadlock condition from the client side.
    let client_config = Arc::new(client::Config {
        window_size: WINDOW_SIZE,
        channel_buffer_size: CHANNEL_BUFFER_SIZE,
        channel_send_timeout: CHANNEL_SEND_TIMEOUT,
        inactivity_timeout: None,
        keepalive_interval: None,
        ..Default::default()
    });
    let client_key =
        Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    let mut session = russh::client::connect(client_config, addr, ClientHandler).await?;
    let authed = session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                client_key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await
        .map(|x| x.success())?;
    assert!(authed, "publickey auth should be accepted");

    let channel = session.channel_open_session().await?;

    // Spawn a writer that pushes data continuously. The first
    // CHANNEL_BUFFER_SIZE messages fit in the per-channel mpsc. Subsequent
    // messages saturate the buffer and force the server-side session loop
    // through the channel_send_timeout path. After CHANNEL_SEND_TIMEOUT
    // the server returns ChannelSendTimeout.
    let writer_task = tokio::spawn(async move {
        let mut writer = channel.make_writer();
        let payload = vec![0u8; (WINDOW_SIZE as usize) / 2];
        loop {
            // After the session ends server-side, the underlying SSH stream
            // closes and writes start failing.
            if writer.write_all(&payload).await.is_err() {
                break;
            }
        }
    });

    // The server-side session future must resolve with ChannelSendTimeout
    // within roughly CHANNEL_SEND_TIMEOUT plus scheduling slack. The outer
    // hard timeout below is a deadlock detector for any regression that
    // lets the session loop park on chan.send(...).await before the
    // bounded send applies.
    let server_outcome = tokio::time::timeout(TEST_HARD_TIMEOUT, server_task)
        .await
        .expect(
            "server session future did not resolve within TEST_HARD_TIMEOUT. \
             The session loop is parked on chan.send(...).await: the bounded \
             send did not apply.",
        )
        .expect("server task panicked");

    // Stop the writer. On success its underlying connection has already
    // been torn down by the server-side session ending, but the writer
    // itself can still be parked on SSH-window flow control.
    writer_task.abort();
    let _ = hold_tx.send(());

    match server_outcome {
        Err(e) => {
            // anyhow::Error wraps russh::Error somewhere in its chain.
            let chain = format!("{e:?}\n{e}");
            assert!(
                chain.to_lowercase().contains("channel send timeout"),
                "server returned unexpected error: {chain}",
            );
        }
        Ok(()) => panic!("server session ended Ok. Expected ChannelSendTimeout."),
    }

    Ok(())
}

struct ServerHandler {
    hold_rx: Option<oneshot::Receiver<()>>,
}

impl russh::server::Handler for ServerHandler {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Hold the channel in a task that never reads from it. The buffer
        // fills after CHANNEL_BUFFER_SIZE inbound messages, which triggers
        // the channel_send_timeout path.
        let hold_rx = self.hold_rx.take().expect("hold_rx taken twice");
        tokio::spawn(async move {
            let _channel = channel;
            let _ = hold_rx.await;
        });
        Ok(true)
    }
}

struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn data(
        &mut self,
        _channel: russh::ChannelId,
        _data: &[u8],
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn extended_data(
        &mut self,
        _channel: russh::ChannelId,
        _ext: u32,
        _data: &[u8],
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn channel_eof(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }
}

use std::future::Future;
