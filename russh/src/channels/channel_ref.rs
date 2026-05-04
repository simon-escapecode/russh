use std::time::Duration;

use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;

use super::WindowSizeRef;
use crate::ChannelMsg;

/// A handle to the [`super::Channel`]'s to be able to transmit messages
/// to it and update it's `window_size`.
#[derive(Debug)]
pub struct ChannelRef {
    pub(super) sender: Sender<ChannelMsg>,
    pub(super) window_size: WindowSizeRef,
}

/// Returned by ChannelRef::send_with_timeout when the bounded wait
/// elapsed without the message being delivered to the per-channel mpsc.
/// The caller propagates this as crate::Error::ChannelSendTimeout so
/// the session loop ends cleanly instead of parking outside its select.
#[derive(Debug)]
pub(crate) struct ChannelSendTimedOut;

impl ChannelRef {
    pub fn new(sender: Sender<ChannelMsg>) -> Self {
        Self {
            sender,
            window_size: WindowSizeRef::new(0),
        }
    }

    pub(crate) fn window_size(&self) -> &WindowSizeRef {
        &self.window_size
    }

    /// Forward an inbound channel message to the per-channel mpsc, capping
    /// the wait at the timeout argument when the buffer is full. A closed
    /// channel is treated as a successful drop. Only an elapsed bounded
    /// wait returns an error.
    pub(crate) async fn send_with_timeout(
        &self,
        msg: ChannelMsg,
        timeout: Duration,
    ) -> Result<(), ChannelSendTimedOut> {
        match self.sender.try_send(msg) {
            Ok(()) => Ok(()),
            Err(TrySendError::Closed(_)) => Ok(()),
            Err(TrySendError::Full(msg)) => {
                match tokio::time::timeout(timeout, self.sender.send(msg)).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Ok(()),
                    Err(_) => Err(ChannelSendTimedOut),
                }
            }
        }
    }
}

impl std::ops::Deref for ChannelRef {
    type Target = Sender<ChannelMsg>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}
