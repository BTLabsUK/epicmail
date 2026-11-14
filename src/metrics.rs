//! Prometheus metrics. Labels never carry addresses, keys, IPs or payloads.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Installs the global Prometheus recorder and describes every metric. Call once per process.
pub fn install() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new().install_recorder()?;
    describe();
    Ok(handle)
}

fn describe() {
    use metrics::{describe_counter, describe_gauge};
    describe_gauge!("epicbox_sockets", "Open websocket connections.");
    describe_gauge!("epicbox_listening_mailboxes", "Mailboxes with at least one listening socket.");
    describe_gauge!("epicbox_mux_holders", "Mailboxes held by a mux/1 socket.");
    describe_gauge!("epicbox_messages_waiting", "Messages stored and not yet collected.");
    describe_gauge!("epicbox_mailboxes_waiting", "Mailboxes with stored messages.");
    describe_gauge!("epicbox_oldest_waiting_seconds", "Age of the oldest stored message.");
    describe_gauge!("epicbox_oldest_unoffered_seconds", "Age of the oldest message never offered to a listener.");
    describe_gauge!("epicbox_forwards_waiting", "Frames queued for other relays.");
    describe_gauge!("epicbox_oldest_forward_seconds", "Age of the oldest queued forward.");
    describe_gauge!("epicbox_forward_lanes", "Peers being forwarded to right now.");
    describe_gauge!("epicbox_tombstones", "Cancelled transactions remembered.");
    describe_gauge!("epicbox_db_bytes", "Size of the SQLite file.");
    describe_gauge!("epicbox_mux_tokens", "Live mux/1 resume tokens.");
    describe_gauge!("epicbox_store_ok", "1 when the last store write succeeded.");
    describe_counter!("epicbox_frames_in_total", "Websocket frames received.");
    describe_counter!("epicbox_frames_out_total", "Websocket frames sent.");
    describe_counter!("epicbox_posts_total", "PostSlate results.");
    describe_counter!("epicbox_subscribe_total", "Subscribe results.");
    describe_counter!("epicbox_deliveries_total", "Messages offered to a listener.");
    describe_counter!("epicbox_made_total", "Messages acknowledged and removed.");
    describe_counter!("epicbox_cancels_total", "Transactions cancelled.");
    describe_counter!("epicbox_forwards_total", "Forward attempts by result.");
    describe_counter!("epicbox_watchdog_closes_total", "Sockets closed because Challenges went unanswered while mail waited.");
    describe_counter!("epicbox_limit_refusals_total", "Requests refused by a limit.");
    describe_counter!("epicbox_mux_sessions_total", "Sockets that switched to mux/1.");
    describe_counter!("epicbox_mux_resumes_total", "mux/1 Resume frames that found their token.");
    describe_counter!("epicbox_http_requests_total", "/v1 requests by route and status.");
}
