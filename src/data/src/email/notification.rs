use crate::email::i18n::passkey_notification::I18nPasskeyNotification;
use crate::email::mailer::{EMail, EmailType};
use crate::email::mailer_callback::EMailCallback;
use crate::entity::theme::ThemeCssFull;
use crate::entity::users::User;
use crate::language::Language;
use crate::rauthy_config::RauthyConfig;
use askama::Template;
use rauthy_notify::{Notification, NotificationLevel};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::error;

#[derive(Default, Template)]
#[template(path = "email/event.html")]
pub struct EMailEventHtml<'a> {
    pub lang: &'a str,
    pub theme_vars: String,
    pub head: &'a str,
    pub row_1: &'a str,
    pub row_2: &'a str,
}

#[derive(Default, Template)]
#[template(path = "email/event.txt")]
pub struct EMailEventTxt<'a> {
    pub head: &'a str,
    pub row_1: &'a str,
    pub row_2: &'a str,
}

pub async fn send_email_notification(
    recipient_name: String,
    address: String,
    tx_email: &mpsc::Sender<(EMail, EMailCallback)>,
    notification: &Notification,
) {
    send_email_notification_lang(recipient_name, address, tx_email, notification, "en").await;
}

async fn send_email_notification_lang(
    recipient_name: String,
    address: String,
    tx_email: &mpsc::Sender<(EMail, EMailCallback)>,
    notification: &Notification,
    lang: &str,
) {
    let text = EMailEventTxt {
        head: &notification.head,
        row_1: &notification.row_1,
        row_2: notification.row_2.as_deref().unwrap_or_default(),
    };

    let theme_vars = ThemeCssFull::find_theme_variables_email()
        .await
        .unwrap_or_default();
    let html = EMailEventHtml {
        lang,
        theme_vars,
        head: text.head,
        row_1: text.row_1,
        row_2: text.row_2,
    };

    let req = EMail {
        typ: EmailType::Notification,
        recipient_name,
        address,
        subject: notification.head.to_string(),
        text: Some(text.render().expect("Template rendering: EMailEventTxt")),
        html: Some(html.render().expect("Template rendering: EMailEventHtml")),
    };

    let res = tx_email
        .send_timeout((req, EMailCallback::None), Duration::from_secs(10))
        .await;
    match res {
        Ok(_) => {}
        Err(ref err) => {
            error!(?err, "sending Event E-Mail notification");
        }
    }
}

pub async fn send_email_passkey_removed(user: &User, passkey_name: &str) {
    let notification = passkey_removed_notification(&user.language, passkey_name);
    send_email_passkey_notification(user, &notification).await;
}

/// Informs the user about a new passkey, see `webauthn.notify_passkey_added`.
pub async fn send_email_passkey_added(user: &User, passkey_name: &str) {
    let notification = passkey_added_notification(&user.language, passkey_name);
    send_email_passkey_notification(user, &notification).await;
}

async fn send_email_passkey_notification(user: &User, notification: &Notification) {
    send_email_notification_lang(
        user.email_recipient_name(),
        user.email.clone(),
        &RauthyConfig::get().tx_email,
        notification,
        user.language.as_str(),
    )
    .await;
}

fn passkey_removed_notification(lang: &Language, passkey_name: &str) -> Notification {
    passkey_notification(I18nPasskeyNotification::removed(lang), passkey_name)
}

fn passkey_added_notification(lang: &Language, passkey_name: &str) -> Notification {
    passkey_notification(I18nPasskeyNotification::added(lang), passkey_name)
}

fn passkey_notification(i18n: I18nPasskeyNotification, passkey_name: &str) -> Notification {
    Notification {
        level: NotificationLevel::Warning,
        head: i18n.head.to_string(),
        row_1: i18n.row_1.replace("{name}", passkey_name),
        row_2: Some(i18n.row_2.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_removed_email_identifies_the_key_and_warns_the_user() {
        let notification = passkey_removed_notification(&Language::En, "security-key");

        assert_eq!(notification.level, NotificationLevel::Warning);
        assert!(notification.row_1.contains("security-key"));
        assert!(notification.row_2.unwrap().contains("immediately"));
    }

    #[test]
    fn passkey_added_email_identifies_the_key_and_warns_the_user() {
        let notification = passkey_added_notification(&Language::En, "phone");

        assert_eq!(notification.level, NotificationLevel::Warning);
        assert_eq!(
            notification.row_1,
            "The passkey 'phone' was added to your account."
        );
        assert!(notification.row_2.unwrap().contains("immediately"));
    }

    #[test]
    fn passkey_emails_use_the_user_language() {
        let added = passkey_added_notification(&Language::De, "Handy");
        assert_eq!(added.head, "Neuer Passkey für Ihr Konto");
        assert_eq!(
            added.row_1,
            "Der Passkey 'Handy' wurde Ihrem Konto hinzugefügt."
        );
        assert!(!added.row_2.unwrap().contains("  "));

        let removed = passkey_removed_notification(&Language::De, "Handy");
        assert_eq!(removed.head, "Passkey aus Ihrem Konto entfernt");
        assert!(removed.row_1.contains("'Handy'"));
    }

    #[test]
    fn passkey_email_texts_exist_for_all_languages() {
        for lang in [
            Language::De,
            Language::En,
            Language::Fr,
            Language::Ja,
            Language::Ko,
            Language::Nb,
            Language::Nl,
            Language::Ru,
            Language::Uk,
            Language::ZhHans,
        ] {
            for i18n in [
                I18nPasskeyNotification::added(&lang),
                I18nPasskeyNotification::removed(&lang),
            ] {
                assert!(!i18n.head.is_empty(), "{lang:?}");
                assert!(i18n.row_1.contains("{name}"), "{lang:?}");
                assert!(!i18n.row_2.is_empty(), "{lang:?}");
            }
        }
    }
}
