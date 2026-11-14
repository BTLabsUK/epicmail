//! Events published after a commit. The /v1 long poll listens here. A slow listener misses
//! events instead of slowing the publisher (`broadcast` drops the oldest), so a listener that
//! lags must re-read the store.

use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum Event {
    /// A message for `queue` was committed.
    MailStored { queue: String },
    /// Messages of a cancelled transaction were removed from these queues.
    TxCancelled { txid: String, queues: Vec<String> },
}

/// A broadcast channel of [`Event`]s. Cloning shares the channel.
#[derive(Clone)]
pub struct Bus {
    tx: broadcast::Sender<Event>,
}

impl Bus {
    /// A bus that keeps the last 4096 events for listeners that fall behind.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self { tx }
    }

    /// Sends to every current subscriber; with none, the event is dropped.
    pub fn publish(&self, e: Event) {
        let _ = self.tx.send(e);
    }

    /// A receiver for events published from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}
