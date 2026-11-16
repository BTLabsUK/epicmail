//! Prometheus metrics. Labels never carry addresses, keys, IPs or payloads.

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Installs the global Prometheus recorder and describes every metric. Call once per process.
pub fn install() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("epicbox_roundtrip_seconds".into()),
            &[5.0, 30.0, 120.0, 600.0, 3600.0, 21_600.0, 86_400.0, 259_200.0],
        )?
        .install_recorder()?;
    describe();
    Ok(handle)
}

fn describe() {
    use metrics::{describe_counter, describe_gauge, describe_histogram};
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
    describe_gauge!("epicbox_store_used_bytes", "Bytes of live data in the SQLite file; store.max_bytes caps posts.");
    describe_gauge!("epicbox_mux_tokens", "Live mux/1 resume tokens.");
    describe_gauge!("epicbox_http_waiting_pulls", "/v1 long polls waiting for mail.");
    describe_gauge!("epicbox_store_ok", "1 when the last store check (/ready probe or expiry sweep) succeeded.");
    describe_counter!("epicbox_frames_in_total", "Websocket frames received.");
    describe_counter!("epicbox_frames_out_total", "Websocket frames sent.");
    describe_gauge!(
        "epicbox_roundtrip_unanswered",
        "Transactions with a txid whose first slate is older than store.unanswered_hours and that have no slate from \
         the other party under that txid and are not cancelled. Counts only transactions stored on this relay."
    );
    describe_histogram!(
        "epicbox_roundtrip_seconds",
        "Seconds from the first slate under a txid to the other party's first slate under it, both stored on this relay."
    );
    describe_counter!("epicbox_posts_total", "PostSlate results, by whether the post carried an epicboxtxid.");
    describe_counter!("epicbox_post_size_total", "Accepted posts by size of the slate body and txid presence.");
    describe_counter!("epicbox_subscribe_total", "Subscribe results.");
    describe_counter!("epicbox_deliveries_total", "Messages offered to a listener.");
    describe_counter!("epicbox_made_total", "Messages acknowledged and removed.");
    describe_counter!("epicbox_cancels_total", "Transactions cancelled.");
    describe_counter!("epicbox_forwards_total", "Forward attempts by result.");
    describe_counter!(
        "epicbox_forward_loops_total",
        "Forwards refused because they came from this relay (another name for it)."
    );
    describe_counter!(
        "epicbox_watchdog_closes_total",
        "Sockets closed because Challenges went unanswered while mail waited."
    );
    describe_counter!("epicbox_limit_refusals_total", "Requests refused by a limit.");
    describe_counter!("epicbox_send_timeouts_total", "Sockets closed because the client stopped reading.");
    describe_counter!("epicbox_mux_sessions_total", "Sockets that switched to mux/1.");
    describe_counter!("epicbox_mux_resumes_total", "mux/1 Resume frames that found their token.");
    describe_counter!(
        "epicbox_mux_tokens_evicted_total",
        "mux/1 resume tokens dropped to stay under mux_token_mailboxes."
    );
    describe_counter!("epicbox_http_requests_total", "/v1 requests by route and status.");
}
