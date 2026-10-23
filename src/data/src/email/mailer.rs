//! The E-Mail sender task.
//!
//! All E-Mails are pushed into an mpsc channel and sent out one after another by [`sender`].
//! Sending mail is a secondary feature: the sender must never take down Rauthy. It therefore
//! never panics because of SMTP / mail API problems. It connects lazily for each E-Mail, tries a
//! bounded number of times ([`SEND_ATTEMPTS`]) and drops the E-Mail if it still fails. A dropped
//! E-Mail is logged at error level without the recipient address, counted in the
//! `rauthy_email_failed_total` metric, reported to a waiting caller via
//! [`EMailCallback::failed`] and emits an `EmailSendError` event. The task keeps running and
//! recovers on its own as soon as the SMTP server is reachable again.

use crate::email::mailer_callback::EMailCallback;
use crate::email::mailer_metrics;
use crate::email::mailer_microsoft_graph::sender_microsoft_graph;
use crate::email::smtp_oauth_token::SmtpOauthToken;
use crate::events::event::Event;
use crate::rauthy_config::{EmailTlsMode, RauthyConfig};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Mechanism;
use lettre::transport::smtp::{authentication, client};
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use serde::Deserialize;
use std::fmt::{Display, Formatter};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// How often a single E-Mail is tried before it is dropped. Together with the SMTP timeout this
/// keeps the worst case for one E-Mail at roughly 25 seconds, which is below the 30 seconds an
/// API caller waits for the result of a synchronous E-Mail (setup mail).
pub(crate) const SEND_ATTEMPTS: u8 = 2;
/// Pause between two attempts - maybe the network just had a short hiccup.
pub(crate) const SEND_RETRY_BACKOFF: Duration = Duration::from_millis(500);
/// Timeout for connecting to / talking with the SMTP server.
const SMTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard upper bound for a single attempt. The SMTP timeout does not cover every phase (for
/// instance a server that accepts the TCP connection but never sends its greeting), and a
/// hanging attempt would block the whole queue.
pub(crate) const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EmailType {
    Custom,
    EmailChangeConfirm,
    EmailChangeInfo,
    EmailRegisteredAlready,
    LoginLocation,
    /// The account setup E-Mail (`new_user` magic link) for a user without any credentials.
    NewUser,
    Notification,
    PasswordReset,
    PasswordResetInfo,
    OtpRequest,
}

impl EmailType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Custom => "Custom",
            Self::EmailChangeConfirm => "EmailChangeConfirm",
            Self::EmailChangeInfo => "EmailChangeInfo",
            Self::EmailRegisteredAlready => "EmailRegisteredAlready",
            Self::LoginLocation => "LoginLocation",
            Self::NewUser => "NewUser",
            Self::Notification => "Notification",
            Self::PasswordReset => "PasswordReset",
            Self::PasswordResetInfo => "PasswordResetInfo",
            Self::OtpRequest => "OtpRequest",
        }
    }
}

impl Display for EmailType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug)]
pub struct EMail {
    pub typ: EmailType,
    pub recipient_name: String,
    pub address: String,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
}

#[derive(Debug, PartialEq, Deserialize)]
pub enum SmtpConnMode {
    Default,
    XOauth2,
    MicrosoftGraph,
    Test,
}

impl From<&str> for SmtpConnMode {
    fn from(s: &str) -> Self {
        match s {
            "default" => Self::Default,
            "xoauth2" => Self::XOauth2,
            "microsoft_graph" => Self::MicrosoftGraph,
            "test" => Self::Test,
            _ => panic!("Invalid smtp_conn_mode, expected one of: default xoauth2 microsoft_graph"),
        }
    }
}

/// The outcome of trying to deliver a single E-Mail.
#[derive(Debug, PartialEq)]
pub(crate) enum Outcome {
    Sent,
    /// All attempts failed. The reason never contains the recipient address.
    Failed(String),
    /// The caller waiting for the result is gone (timed out) - the E-Mail was not sent.
    Abandoned,
}

/// A single delivery attempt for one E-Mail. Implementations connect lazily.
pub(crate) trait Attempt {
    async fn attempt(&mut self) -> Result<(), String>;
}

/// Tries to deliver one E-Mail up to `attempts` times, each bounded by `attempt_timeout`, and
/// updates the `rauthy_email_smtp_up` gauge after each attempt. Stops early when nobody waits
/// for the result anymore.
pub(crate) async fn try_deliver<A: Attempt>(
    callback: &EMailCallback,
    attempts: u8,
    backoff: Duration,
    attempt_timeout: Duration,
    sender: &mut A,
) -> Outcome {
    let mut last_err = String::from("no attempt was made");

    for i in 0..attempts {
        if i > 0 {
            tokio::time::sleep(backoff).await;
        }
        if callback.is_abandoned() {
            return Outcome::Abandoned;
        }

        let res = match tokio::time::timeout(attempt_timeout, sender.attempt()).await {
            Ok(res) => res,
            Err(_) => Err(format!(
                "no result within {} seconds",
                attempt_timeout.as_secs()
            )),
        };
        match res {
            Ok(()) => {
                mailer_metrics::set_smtp_up(true);
                return Outcome::Sent;
            }
            Err(err) => {
                mailer_metrics::set_smtp_up(false);
                warn!(
                    attempt = i + 1,
                    attempts,
                    error = err,
                    "Could not send E-Mail"
                );
                last_err = err;
            }
        }
    }

    Outcome::Failed(last_err)
}

/// Logs the outcome, updates the counters and reports the result to the callback. Returns
/// `true` if an `EmailSendError` event should be emitted.
pub(crate) async fn record_outcome(
    typ: EmailType,
    callback: EMailCallback,
    outcome: Outcome,
) -> bool {
    match outcome {
        Outcome::Sent => {
            info!(email_type = %typ, "E-Mail sent successfully");
            mailer_metrics::inc_sent(typ);
            callback.call().await;
            false
        }
        Outcome::Failed(reason) => {
            error!(
                email_type = %typ,
                error = reason,
                "Could not send E-Mail even after retrying - dropping it"
            );
            mailer_metrics::inc_failed(typ);
            callback.failed(reason);
            true
        }
        Outcome::Abandoned => {
            // the waiting caller has already reported the failure (and the event)
            warn!(
                email_type = %typ,
                "Nobody waits for the result of this E-Mail anymore - dropping it"
            );
            mailer_metrics::inc_failed(typ);
            callback.failed("timeout".to_string());
            false
        }
    }
}

/// Records the outcome and emits the `EmailSendError` event if needed.
async fn finish(typ: EmailType, address: &str, callback: EMailCallback, outcome: Outcome) {
    if record_outcome(typ, callback, outcome).await
        && let Err(err) = Event::email_send_err(typ, address).send().await
    {
        error!(?err, "Could not push EmailSendError event");
    }
}

/// Removes the recipient address from an error message. SMTP servers often echo the address
/// in their replies, which must not end up in logs, events or API responses.
pub(crate) fn redact_address(msg: &str, address: &str) -> String {
    if address.is_empty() {
        return msg.to_string();
    }
    let lower_msg = msg.to_lowercase();
    let lower_addr = address.to_lowercase();
    // lowercasing may change byte lengths for non-ASCII -> only do the case-insensitive
    // replacement when it is safe, otherwise fall back to an exact replacement
    if lower_msg.len() != msg.len() || lower_addr.len() != address.len() {
        return msg.replace(address, "<recipient>");
    }

    let mut res = String::with_capacity(msg.len());
    let mut idx = 0;
    while let Some(pos) = lower_msg[idx..].find(&lower_addr) {
        let start = idx + pos;
        res.push_str(&msg[idx..start]);
        res.push_str("<recipient>");
        idx = start + address.len();
    }
    res.push_str(&msg[idx..]);
    res
}

pub async fn sender(rx: mpsc::Receiver<(EMail, EMailCallback)>) {
    debug!("E-Mail sender started");

    let vars = &RauthyConfig::get().vars.email;
    let url = &vars.smtp_url;
    if url.is_none() && vars.smtp_conn_mode != SmtpConnMode::MicrosoftGraph {
        sender_test_debug(rx).await;
    } else {
        match vars.smtp_conn_mode {
            SmtpConnMode::Default | SmtpConnMode::XOauth2 => {
                sender_default_smtp(url.as_deref().unwrap_or_default(), rx).await
            }
            SmtpConnMode::MicrosoftGraph => sender_microsoft_graph(rx).await,
            SmtpConnMode::Test => sender_test_debug(rx).await,
        }
    }
}

async fn sender_test_debug(mut rx: mpsc::Receiver<(EMail, EMailCallback)>) {
    warn!("SMTP_URL is not configured or test mode is set, cannot send out any E-Mails!");

    loop {
        if let Some((email, callback)) = rx.recv().await {
            debug!(email_type = %email.typ, "New E-Mail - not sent in test / debug mode");
            // A waiting caller gets success, nothing else is executed, as before.
            callback.report_handled();
        } else {
            warn!("Received 'None' in email 'sender' - exiting");
            return;
        }
    }
}

/// Parses the configured `SMTP_FROM`. Never panics.
pub(crate) fn parse_from() -> Result<Mailbox, String> {
    RauthyConfig::get()
        .vars
        .email
        .smtp_from
        .as_ref()
        .parse::<Mailbox>()
        .map_err(|err| format!("SMTP_FROM could not be parsed correctly: {err}"))
}

fn build_message(from: &Mailbox, req: EMail) -> Result<lettre::Message, String> {
    let address = req
        .address
        .parse::<Address>()
        .map_err(|_| "invalid recipient address".to_string())?;
    let to = Mailbox::new(Some(req.recipient_name), address);

    let builder = lettre::Message::builder()
        .from(from.clone())
        .to(to)
        .subject(req.subject);

    let res = match (req.text, req.html) {
        (Some(text), Some(html)) => {
            builder.multipart(MultiPart::alternative_plain_html(text, html))
        }
        (None, Some(html)) => builder.singlepart(SinglePart::html(html)),
        (Some(text), None) => builder.singlepart(SinglePart::plain(text)),
        (None, None) => {
            warn!("Sending E-Mail with empty body!");
            builder.singlepart(SinglePart::plain(String::default()))
        }
    };
    res.map_err(|err| format!("Error building the E-Mail: {err}"))
}

struct SmtpAttempt<'a> {
    smtp_url: &'a str,
    transport: &'a mut Option<AsyncSmtpTransport<Tokio1Executor>>,
    message: &'a lettre::Message,
    address: &'a str,
}

impl Attempt for SmtpAttempt<'_> {
    async fn attempt(&mut self) -> Result<(), String> {
        if self.transport.is_none() {
            *self.transport = Some(build_smtp_transport(self.smtp_url).await?);
        }
        let Some(transport) = self.transport.as_ref() else {
            return Err("no SMTP transport".to_string());
        };

        match transport.send(self.message.clone()).await {
            Ok(_) => Ok(()),
            Err(err) => {
                // Rebuild the transport for the next attempt. This matters for XOAUTH2, which
                // uses expiring tokens. The transport opens a new connection per E-Mail anyway.
                *self.transport = None;
                Err(redact_address(&err.to_string(), self.address))
            }
        }
    }
}

async fn sender_default_smtp(smtp_url: &str, mut rx: mpsc::Receiver<(EMail, EMailCallback)>) {
    let from = parse_from();
    if let Err(err) = &from {
        error!("{err} - E-Mails cannot be sent");
    }

    // Non-blocking startup probe: only for logging and the `rauthy_email_smtp_up` gauge.
    // A failure here must never stop Rauthy, the connection is retried for every E-Mail.
    let mut transport = probe_smtp(smtp_url).await;

    loop {
        debug!("Listening for incoming send E-Mail requests");
        let Some((req, callback)) = rx.recv().await else {
            warn!("Received 'None' in email 'sender' - exiting");
            break;
        };

        let typ = req.typ;
        let address = req.address.clone();
        debug!(email_type = %typ, "New E-Mail");

        let message = match &from {
            Ok(from) => build_message(from, req),
            Err(err) => Err(err.clone()),
        };
        let outcome = match message {
            Ok(message) => {
                let mut attempt = SmtpAttempt {
                    smtp_url,
                    transport: &mut transport,
                    message: &message,
                    address: &address,
                };
                try_deliver(
                    &callback,
                    SEND_ATTEMPTS,
                    SEND_RETRY_BACKOFF,
                    ATTEMPT_TIMEOUT,
                    &mut attempt,
                )
                .await
            }
            Err(err) => Outcome::Failed(err),
        };

        finish(typ, &address, callback, outcome).await;
    }
}

/// Tests the SMTP connection once. Never panics, never retries.
async fn probe_smtp(smtp_url: &str) -> Option<AsyncSmtpTransport<Tokio1Executor>> {
    let mode = &RauthyConfig::get().vars.email.smtp_tls_mode;
    let transport = match build_smtp_transport(smtp_url).await {
        Ok(t) => t,
        Err(err) => {
            mailer_metrics::set_smtp_up(false);
            error!(
                error = err,
                "Cannot build the SMTP transport - E-Mails will fail until this is fixed"
            );
            return None;
        }
    };

    match transport.test_connection().await {
        Ok(true) => {
            mailer_metrics::set_smtp_up(true);
            info!("Successfully connected to {smtp_url} via {mode}");
        }
        Ok(false) => {
            mailer_metrics::set_smtp_up(false);
            error!(
                "Could not connect to {smtp_url} via {mode}: Connected but SMTP test failed. \
                Rauthy keeps running and retries for each E-Mail."
            );
        }
        Err(err) => {
            mailer_metrics::set_smtp_up(false);
            error!(
                ?err,
                "Could not connect to {smtp_url} via {mode}. Check your network and credentials. \
                Rauthy keeps running and retries for each E-Mail."
            );
        }
    }
    Some(transport)
}

/// Builds the SMTP transport from the config. Does not open a connection, apart from fetching
/// an XOAUTH2 token if configured. Never panics.
async fn build_smtp_transport(
    smtp_url: &str,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    let vars = &RauthyConfig::get().vars.email;

    if vars.smtp_tls_mode == EmailTlsMode::DangerInsecure {
        let port = vars.smtp_port.unwrap_or(1025);
        return Ok(
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_url)
                .port(port)
                .timeout(Some(SMTP_TIMEOUT))
                .build(),
        );
    }

    let username = vars
        .smtp_username
        .as_deref()
        .ok_or_else(|| "SMTP_USERNAME is not set".to_string())?
        .trim()
        .to_string();

    let mut mechanisms = Vec::with_capacity(2);
    let creds = if vars.smtp_conn_mode == SmtpConnMode::XOauth2 {
        mechanisms.push(Mechanism::Xoauth2);

        let token = SmtpOauthToken::get().await.map_err(|err| {
            format!(
                "Could not retrieve a `client_credentials` token for SMTP XOAUTH2: {}",
                err.message
            )
        })?;
        authentication::Credentials::new(username, token.access_token)
    } else {
        mechanisms.push(Mechanism::Plain);
        mechanisms.push(Mechanism::Login);

        let password = vars
            .smtp_password
            .as_deref()
            .ok_or_else(|| "SMTP_PASSWORD is not set".to_string())?
            .trim()
            .to_string();
        authentication::Credentials::new(username, password)
    };

    let mut builder = if vars.smtp_tls_mode == EmailTlsMode::Tls {
        AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_url)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(smtp_url)
    }
    .map_err(|err| format!("Invalid 'SMTP_URL': {err}"))?;

    if let Some(port) = vars.smtp_port {
        builder = builder.port(port);
    }

    if let Some(root_ca) = &vars.root_ca {
        let cert = client::Certificate::from_pem(root_ca.as_bytes())
            .map_err(|err| format!("Invalid `email.root_ca` for SMTP connections: {err}"))?;

        let params = client::TlsParameters::builder(smtp_url.to_string())
            .add_root_certificate(cert)
            .build_rustls()
            .map_err(|err| {
                format!("Cannot build TLS parameters with custom `email.root_ca`: {err}")
            })?;

        builder = builder.tls(client::Tls::Required(params));
    }

    Ok(builder
        .authentication(mechanisms)
        .credentials(creds)
        .timeout(Some(SMTP_TIMEOUT))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::mailer_callback::EMailResult;
    use std::collections::VecDeque;

    const TO: Duration = Duration::from_secs(5);

    struct FakeSender {
        results: VecDeque<Result<(), String>>,
        calls: usize,
        /// drops the receiver of the callback after this many calls
        drop_rx_after: Option<(usize, Option<tokio::sync::oneshot::Receiver<EMailResult>>)>,
        /// never returns from `attempt()`
        hang: bool,
    }

    impl FakeSender {
        fn new(results: Vec<Result<(), String>>) -> Self {
            Self {
                results: results.into(),
                calls: 0,
                drop_rx_after: None,
                hang: false,
            }
        }
    }

    impl Attempt for FakeSender {
        async fn attempt(&mut self) -> Result<(), String> {
            self.calls += 1;
            if self.hang {
                std::future::pending::<()>().await;
            }
            if let Some((after, rx)) = &mut self.drop_rx_after
                && *after == self.calls
            {
                rx.take();
            }
            self.results
                .pop_front()
                .unwrap_or_else(|| Err("exhausted".to_string()))
        }
    }

    // All metric assertions live in one test, because the metrics are process-wide statics.
    #[tokio::test]
    async fn test_try_deliver_and_record() {
        let backoff = Duration::from_millis(1);

        // success on the first attempt
        let (cb, rx) = EMailCallback::result();
        let mut s = FakeSender::new(vec![Ok(())]);
        let outcome = try_deliver(&cb, SEND_ATTEMPTS, backoff, TO, &mut s).await;
        assert_eq!(outcome, Outcome::Sent);
        assert_eq!(s.calls, 1);
        assert_eq!(mailer_metrics::smtp_up(), 1);
        let sent_before = mailer_metrics::sent(EmailType::NewUser);
        assert!(!record_outcome(EmailType::NewUser, cb, outcome).await);
        assert_eq!(mailer_metrics::sent(EmailType::NewUser), sent_before + 1);
        assert_eq!(rx.await.unwrap(), EMailResult::Sent);

        // success after a retry
        let (cb, rx) = EMailCallback::result();
        let mut s = FakeSender::new(vec![Err("hiccup".to_string()), Ok(())]);
        let outcome = try_deliver(&cb, SEND_ATTEMPTS, backoff, TO, &mut s).await;
        assert_eq!(outcome, Outcome::Sent);
        assert_eq!(s.calls, 2);
        assert_eq!(mailer_metrics::smtp_up(), 1);
        record_outcome(EmailType::NewUser, cb, outcome).await;
        assert_eq!(rx.await.unwrap(), EMailResult::Sent);

        // all attempts fail -> dropped, reported, counted, event requested
        let (cb, rx) = EMailCallback::result();
        let mut s = FakeSender::new(vec![
            Err("connection refused".to_string()),
            Err("connection refused".to_string()),
            Ok(()),
        ]);
        let outcome = try_deliver(&cb, SEND_ATTEMPTS, backoff, TO, &mut s).await;
        assert_eq!(outcome, Outcome::Failed("connection refused".to_string()));
        assert_eq!(s.calls, SEND_ATTEMPTS as usize);
        assert_eq!(mailer_metrics::smtp_up(), 0);
        let failed_before = mailer_metrics::failed(EmailType::NewUser);
        assert!(record_outcome(EmailType::NewUser, cb, outcome).await);
        assert_eq!(
            mailer_metrics::failed(EmailType::NewUser),
            failed_before + 1
        );
        assert_eq!(
            rx.await.unwrap(),
            EMailResult::Failed("connection refused".to_string())
        );

        // the sender recovers on the next E-Mail once SMTP is reachable again
        let (cb, rx) = EMailCallback::result();
        let mut s = FakeSender::new(vec![Ok(())]);
        let outcome = try_deliver(&cb, SEND_ATTEMPTS, backoff, TO, &mut s).await;
        assert_eq!(outcome, Outcome::Sent);
        assert_eq!(mailer_metrics::smtp_up(), 1);
        record_outcome(EmailType::NewUser, cb, outcome).await;
        assert_eq!(rx.await.unwrap(), EMailResult::Sent);

        // the caller timed out after the first failed attempt -> no second attempt
        let (cb, rx) = EMailCallback::result();
        let mut s = FakeSender::new(vec![Err("timeout".to_string()), Ok(())]);
        s.drop_rx_after = Some((1, Some(rx)));
        let outcome = try_deliver(&cb, SEND_ATTEMPTS, backoff, TO, &mut s).await;
        assert_eq!(outcome, Outcome::Abandoned);
        assert_eq!(s.calls, 1);
        // no event for abandoned mails, the waiting caller emits it
        assert!(!record_outcome(EmailType::NewUser, cb, outcome).await);

        // fire-and-forget E-Mails without a waiting caller are never abandoned
        let mut s = FakeSender::new(vec![Err("down".to_string()), Err("down".to_string())]);
        let outcome = try_deliver(&EMailCallback::None, SEND_ATTEMPTS, backoff, TO, &mut s).await;
        assert_eq!(outcome, Outcome::Failed("down".to_string()));
        assert_eq!(s.calls, 2);
    }

    // A server that never answers must not block the queue: every attempt is bounded.
    #[tokio::test(start_paused = true)]
    async fn test_try_deliver_hanging_attempt() {
        let mut s = FakeSender::new(vec![]);
        s.hang = true;
        let start = tokio::time::Instant::now();
        let outcome = try_deliver(
            &EMailCallback::None,
            SEND_ATTEMPTS,
            SEND_RETRY_BACKOFF,
            ATTEMPT_TIMEOUT,
            &mut s,
        )
        .await;
        assert_eq!(
            outcome,
            Outcome::Failed("no result within 12 seconds".to_string())
        );
        assert_eq!(s.calls, SEND_ATTEMPTS as usize);
        // well below the 30 seconds a setup mail caller waits
        assert!(start.elapsed() < Duration::from_secs(30));
    }

    #[test]
    fn test_redact_address() {
        let addr = "Synthetic.User@example.org";
        assert_eq!(
            redact_address(
                "permanent error (550): 5.1.1 <synthetic.user@example.org>: Recipient rejected",
                addr
            ),
            "permanent error (550): 5.1.1 <<recipient>>: Recipient rejected"
        );
        assert_eq!(
            redact_address(
                "a Synthetic.User@example.org b SYNTHETIC.USER@EXAMPLE.ORG",
                addr
            ),
            "a <recipient> b <recipient>"
        );
        assert_eq!(
            redact_address("connection refused", addr),
            "connection refused"
        );
        assert_eq!(redact_address("x", ""), "x");
    }

    #[test]
    fn test_build_message_never_panics() {
        let from: Mailbox = "Rauthy <rauthy@example.org>".parse().unwrap();

        // odd recipient names must not fail, they are not parsed
        let msg = build_message(
            &from,
            EMail {
                typ: EmailType::NewUser,
                recipient_name: "Max <\"Muster\"> , ; Mann".to_string(),
                address: "max@example.org".to_string(),
                subject: "Subject".to_string(),
                text: Some("text".to_string()),
                html: Some("<p>html</p>".to_string()),
            },
        );
        assert!(msg.is_ok());

        let err = build_message(
            &from,
            EMail {
                typ: EmailType::NewUser,
                recipient_name: "Max".to_string(),
                address: "not an address".to_string(),
                subject: "Subject".to_string(),
                text: None,
                html: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, "invalid recipient address");
    }
}
