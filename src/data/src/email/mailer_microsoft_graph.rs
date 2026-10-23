use crate::email::mailer::{
    Attempt, EMail, EmailType, Outcome, SEND_ATTEMPTS, SEND_RETRY_BACKOFF, parse_from,
    record_outcome, redact_address, try_deliver,
};
use crate::email::mailer_callback::EMailCallback;
use crate::email::smtp_oauth_token::SmtpOauthToken;
use crate::events::event::Event;
use crate::rauthy_config::RauthyConfig;
use rauthy_common::HTTP_CLIENT;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Serialize)]
struct EmailAddr {
    address: String,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Recipient {
    email_address: EmailAddr,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum EmailContentType {
    Text,
    Html,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailBody {
    content: String,
    content_type: EmailContentType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftEmail<'a> {
    bcc_recipients: Vec<Recipient>,
    body: EmailBody,
    cc_recipients: Vec<Recipient>,
    reply_to: Vec<&'a Recipient>,
    // sender: Recipient,
    subject: String,
    to_recipients: Vec<Recipient>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftMessage<'a> {
    message: MicrosoftEmail<'a>,
    save_to_sent_items: bool,
}

pub async fn sender_microsoft_graph(mut rx: mpsc::Receiver<(EMail, EMailCallback)>) {
    let from = match parse_from() {
        Ok(from) => Ok(Recipient {
            email_address: EmailAddr {
                address: from.email.to_string(),
                name: from.name,
            },
        }),
        Err(err) => {
            error!("{err} - E-Mails cannot be sent");
            Err(err)
        }
    };

    info!("Using Microsoft Graph API to send out E-Mails");

    loop {
        debug!("Listening for incoming send E-Mail requests");
        let Some((req, callback)) = rx.recv().await else {
            warn!("Received 'None' in email 'sender' - exiting");
            break;
        };

        let typ = req.typ;
        let address = req.address.clone();
        debug!(email_type = %typ, "New E-Mail");

        let from = match &from {
            Ok(from) => from,
            Err(err) => {
                let outcome = Outcome::Failed(err.clone());
                if record_outcome(typ, callback, outcome).await {
                    send_err_event(typ, &address).await;
                }
                continue;
            }
        };

        let body = if let Some(content) = req.html {
            EmailBody {
                content,
                content_type: EmailContentType::Html,
            }
        } else if let Some(content) = req.text {
            EmailBody {
                content,
                content_type: EmailContentType::Text,
            }
        } else {
            warn!("Sending E-Mail with empty body!");
            EmailBody {
                content: String::default(),
                content_type: EmailContentType::Text,
            }
        };

        let email = MicrosoftMessage {
            message: MicrosoftEmail {
                bcc_recipients: Vec::default(),
                body,
                cc_recipients: Vec::default(),
                reply_to: vec![from],
                subject: req.subject,
                to_recipients: vec![Recipient {
                    email_address: EmailAddr {
                        address: req.address,
                        name: Some(req.recipient_name),
                    },
                }],
            },
            save_to_sent_items: false,
        };

        let mut attempt = GraphAttempt {
            email: &email,
            address: &address,
        };
        let outcome = try_deliver(&callback, SEND_ATTEMPTS, SEND_RETRY_BACKOFF, &mut attempt).await;
        if record_outcome(typ, callback, outcome).await {
            send_err_event(typ, &address).await;
        }
    }
}

async fn send_err_event(typ: EmailType, address: &str) {
    if let Err(err) = Event::email_send_err(typ, address).send().await {
        error!(?err, "Could not push EmailSendError event");
    }
}

struct GraphAttempt<'a> {
    email: &'a MicrosoftMessage<'a>,
    address: &'a str,
}

impl Attempt for GraphAttempt<'_> {
    async fn attempt(&mut self) -> Result<(), String> {
        send_email(self.email)
            .await
            .map_err(|err| redact_address(&err.message, self.address))
    }
}

async fn send_email(email: &MicrosoftMessage<'_>) -> Result<(), ErrorResponse> {
    let token = SmtpOauthToken::get().await?;

    let Some(uri) = RauthyConfig::get().vars.email.microsoft_graph_uri.as_ref() else {
        return Err(ErrorResponse::new(
            ErrorResponseType::Internal,
            "`email.microsoft_graph_uri` is not set",
        ));
    };
    debug!("SendMail URI: {uri}");

    let res = HTTP_CLIENT
        .get()
        .ok_or_else(|| {
            ErrorResponse::new(
                ErrorResponseType::Internal,
                "HTTP client is not initialized",
            )
        })?
        .post(uri)
        .bearer_auth(token.access_token)
        .json(&email)
        .send()
        .await?;

    if res.status().is_success() {
        Ok(())
    } else {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        Err(ErrorResponse::new(
            ErrorResponseType::Connection,
            format!("Error sending E-Mail via Microsoft Graph: HTTP {status} {body}"),
        ))
    }
}
