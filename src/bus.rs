//! Events published after a commit. The /v1 long poll listens here today; webhooks would
//! subscribe the same way (docs/webhooks.md).

use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum Event {
    /// A message for `queue` was committed.
    MailStored { queue: String },
    /// Messages of a cancelled transaction were removed from these queues.
    TxCancelled { txid: String, queues: Vec<String> },
}

#[derive(Clone)]
pub struct Bus {
    tx: broadcast::Sender<Event>,
}

impl Bus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self { tx }
    }

    pub fn publish(&self, e: Event) {
        let _ = self.tx.send(e);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}
