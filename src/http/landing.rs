//! The page a browser gets at `/`: what the relay is and whether it works.
//!
//! One static document compiled into the binary. Its script reads `/health`, `/ready` and
//! `/.well-known/epicbox.json` and opens one websocket for the first Challenge, so the page
//! shows nothing the relay does not already publish. It loads nothing from other hosts, and
//! the Content-Security-Policy allows only the page's own script and style, each by hash.

use std::sync::LazyLock;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use sha2::{Digest, Sha256};

struct Page {
    body: String,
    csp: HeaderValue,
}

static PAGE: LazyLock<Page> = LazyLock::new(|| {
    // A browser hashes inline script and style with LF line ends; a checkout may have CRLF.
    let body = include_str!("landing.html").replace("\r\n", "\n");
    let csp = format!(
        "default-src 'none'; script-src '{}'; style-src '{}'; img-src data:; connect-src 'self'; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        source_hash(inline(&body, "script")),
        source_hash(inline(&body, "style")),
    );
    Page { body, csp: HeaderValue::from_str(&csp).expect("the policy is ASCII") }
});

/// The text of the page's one `<tag>` element.
fn inline<'a>(page: &'a str, tag: &str) -> &'a str {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let start = page.find(&open).expect("the page has the element") + open.len();
    let end = start + page[start..].find(&close).expect("the element is closed");
    &page[start..end]
}

fn source_hash(text: &str) -> String {
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(Sha256::digest(text.as_bytes())))
}

/// A browser asks for HTML; probes, `curl` and wallets do not.
pub(super) fn wanted(headers: &HeaderMap) -> bool {
    headers.get_all(header::ACCEPT).iter().filter_map(|v| v.to_str().ok()).any(|v| v.contains("text/html"))
}

pub(super) fn page() -> Response {
    let p = &*PAGE;
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8")),
            (header::CONTENT_SECURITY_POLICY, p.csp.clone()),
            (header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
            (header::VARY, HeaderValue::from_static("Accept")),
        ],
        p.body.clone(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_is_self_contained() {
        let p = &*PAGE;
        // One script and one style, so the two hashes in the policy cover all of it.
        for tag in ["script", "style"] {
            assert_eq!(p.body.matches(&format!("<{tag}")).count(), 1, "{tag}");
        }
        assert_eq!(p.csp.to_str().unwrap().matches("'sha256-").count(), 2);
        // Nothing is fetched from another host, and no inline handler or style attribute would
        // pass the policy.
        for needle in [" src=", "@import", "url(", " style=", " onclick=", " onload="] {
            assert!(!p.body.contains(needle), "{needle}");
        }
        let links: Vec<&str> = p.body.match_indices("href=\"").map(|(i, _)| &p.body[i + 6..i + 30]).collect();
        assert!(links.iter().all(|l| l.starts_with("data:") || l.starts_with("https://")), "{links:?}");
        assert!(!p.body.contains('\r'));
    }

    #[test]
    fn only_a_browser_gets_it() {
        let mut h = HeaderMap::new();
        assert!(!wanted(&h));
        h.insert(header::ACCEPT, "*/*".parse().unwrap());
        assert!(!wanted(&h));
        h.insert(header::ACCEPT, "text/html,application/xhtml+xml,*/*;q=0.8".parse().unwrap());
        assert!(wanted(&h));
    }
}
