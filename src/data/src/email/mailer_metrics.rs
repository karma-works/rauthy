//! Prometheus metrics of the E-Mail sender.
//!
//! The values are always recorded (cheap atomics). They are only exposed when
//! `server.metrics_enable` is set, by registering them into the shared metrics registry with
//! [`register`]. Labels never contain addresses or user ids, only the [`EmailType`].

use crate::email::mailer::EmailType;
use prometheus::{IntCounterVec, IntGauge, Opts, Registry};
use std::sync::LazyLock;
use tracing::error;

static EMAIL_SENT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "rauthy_email_sent_total",
            "E-Mails accepted by the SMTP server / mail API",
        ),
        &["type"],
    )
    .expect("valid metric definition")
});

static EMAIL_FAILED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "rauthy_email_failed_total",
            "E-Mails that could not be sent and were dropped",
        ),
        &["type"],
    )
    .expect("valid metric definition")
});

static SMTP_UP: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "rauthy_email_smtp_up",
        "1 if the last SMTP connection / send succeeded, 0 if it failed or nothing was tried yet",
    )
    .expect("valid metric definition")
});

/// Registers the E-Mail metrics into the given registry. Call it once.
pub fn register(registry: &Registry) {
    for collector in [
        Box::new(EMAIL_SENT.clone()) as Box<dyn prometheus::core::Collector>,
        Box::new(EMAIL_FAILED.clone()),
        Box::new(SMTP_UP.clone()),
    ] {
        if let Err(err) = registry.register(collector) {
            error!(?err, "Cannot register E-Mail metrics");
        }
    }
}

pub fn inc_sent(typ: EmailType) {
    EMAIL_SENT.with_label_values(&[typ.as_str()]).inc();
}

pub fn inc_failed(typ: EmailType) {
    EMAIL_FAILED.with_label_values(&[typ.as_str()]).inc();
}

pub fn set_smtp_up(up: bool) {
    SMTP_UP.set(if up { 1 } else { 0 });
}

#[cfg(test)]
pub(crate) fn sent(typ: EmailType) -> u64 {
    EMAIL_SENT.with_label_values(&[typ.as_str()]).get()
}

#[cfg(test)]
pub(crate) fn failed(typ: EmailType) -> u64 {
    EMAIL_FAILED.with_label_values(&[typ.as_str()]).get()
}

#[cfg(test)]
pub(crate) fn smtp_up() -> i64 {
    SMTP_UP.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_gather() {
        let registry = Registry::new();
        register(&registry);
        inc_sent(EmailType::Custom);
        inc_failed(EmailType::Custom);
        set_smtp_up(true);

        let names = registry
            .gather()
            .into_iter()
            .map(|mf| mf.name().to_string())
            .collect::<Vec<_>>();
        assert!(names.contains(&"rauthy_email_sent_total".to_string()));
        assert!(names.contains(&"rauthy_email_failed_total".to_string()));
        assert!(names.contains(&"rauthy_email_smtp_up".to_string()));
    }
}
