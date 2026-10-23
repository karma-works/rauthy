use crate::entity::pwd_exp_mails::PasswordExpMail;
use rauthy_error::ErrorResponse;
use tokio::sync::oneshot;
use tracing::error;

/// The final result of a single E-Mail as reported by the sender task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EMailResult {
    /// The SMTP server / mail API accepted the E-Mail, or the test / debug sender handled it.
    Sent,
    /// The E-Mail could not be sent and was dropped. The reason never contains the recipient.
    Failed(String),
}

/// Used for callbacks after an E-Mail was sent, or could not be sent.
#[derive(Debug)]
pub enum EMailCallback {
    None,
    PasswordExp {
        user_id: String,
    },
    /// Reports the final result of this E-Mail to a waiting caller.
    Result(oneshot::Sender<EMailResult>),
}

impl EMailCallback {
    /// Creates a callback that reports the result, together with the receiving side.
    pub fn result() -> (Self, oneshot::Receiver<EMailResult>) {
        let (tx, rx) = oneshot::channel();
        (Self::Result(tx), rx)
    }

    /// `true` if nobody waits for the result anymore (for instance because the caller timed
    /// out). Such an E-Mail should not be sent anymore, the caller has already reported failure.
    pub fn is_abandoned(&self) -> bool {
        match self {
            Self::Result(tx) => tx.is_closed(),
            Self::None | Self::PasswordExp { .. } => false,
        }
    }

    /// Must be called after an E-Mail was sent successfully.
    pub async fn call(self) {
        if let Err(err) = self.call_inner().await {
            error!("Error executing E-Mail callback: {err:?}");
        }
    }

    /// Must be called when an E-Mail could not be sent and was dropped.
    pub fn failed(self, reason: String) {
        if let Self::Result(tx) = self {
            // the receiver may be gone already -> nothing to report then
            let _ = tx.send(EMailResult::Failed(reason));
        }
    }

    /// Only reports success to a waiting caller without executing any other side effects.
    /// Used by the test / debug sender, which does not actually send anything.
    pub fn report_handled(self) {
        if let Self::Result(tx) = self {
            let _ = tx.send(EMailResult::Sent);
        }
    }

    #[inline]
    async fn call_inner(self) -> Result<(), ErrorResponse> {
        match self {
            EMailCallback::None => {}
            EMailCallback::PasswordExp { user_id } => {
                PasswordExpMail::upsert_now(user_id).await?;
            }
            EMailCallback::Result(tx) => {
                let _ = tx.send(EMailResult::Sent);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_result_sent() {
        let (cb, rx) = EMailCallback::result();
        assert!(!cb.is_abandoned());
        cb.call().await;
        assert_eq!(rx.await.unwrap(), EMailResult::Sent);
    }

    #[tokio::test]
    async fn test_result_failed() {
        let (cb, rx) = EMailCallback::result();
        cb.failed("smtp down".to_string());
        assert_eq!(
            rx.await.unwrap(),
            EMailResult::Failed("smtp down".to_string())
        );
    }

    #[tokio::test]
    async fn test_result_handled() {
        let (cb, rx) = EMailCallback::result();
        cb.report_handled();
        assert_eq!(rx.await.unwrap(), EMailResult::Sent);
    }

    #[test]
    fn test_abandoned() {
        let (cb, rx) = EMailCallback::result();
        drop(rx);
        assert!(cb.is_abandoned());
        // must not panic without a receiver
        cb.failed("gone".to_string());

        assert!(!EMailCallback::None.is_abandoned());
    }
}
