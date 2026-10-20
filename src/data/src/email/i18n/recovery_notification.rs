use crate::language::Language;

/// Texts for the E-Mails around recovery codes. German and English, other languages fall back
/// to English.
#[derive(Debug, PartialEq)]
pub struct I18nRecoveryNotification {
    pub head: &'static str,
    pub row_1: &'static str,
    pub row_2: &'static str,
}

impl I18nRecoveryNotification {
    /// `{code}` and `{minutes}` in `row_1` are replaced.
    pub fn mail_code(lang: &Language) -> Self {
        let (head, row_1, row_2) = match lang {
            Language::De => (
                "Ihr Bestätigungscode zur Wiederherstellung",
                "Ein Wiederherstellungscode Ihres Kontos wurde soeben verwendet. Ihr \
                Bestätigungscode lautet {code}. Er gilt {minutes} Minuten.",
                "Wenn Sie das nicht selbst waren, geben Sie den Code nicht weiter und wenden Sie \
                sich sofort an Ihre Administration. Der verwendete Wiederherstellungscode ist \
                verbraucht; erzeugen Sie neue Codes.",
            ),
            _ => (
                "Your recovery confirmation code",
                "A recovery code of your account has just been used. Your confirmation code is \
                {code}. It is valid for {minutes} minutes.",
                "If this was not you, do not share the code and contact your administrator \
                immediately. The used recovery code is gone; create new codes.",
            ),
        };
        Self { head, row_1, row_2 }
    }

    pub fn regenerated(lang: &Language) -> Self {
        let (head, row_1, row_2) = match lang {
            Language::De => (
                "Neue Wiederherstellungscodes für Ihr Konto",
                "Für Ihr Konto wurden neue Wiederherstellungscodes erzeugt. Alle früheren Codes \
                sind ab sofort ungültig.",
                "Wenn Sie das nicht selbst waren, wenden Sie sich bitte sofort an Ihre \
                Administration.",
            ),
            _ => (
                "New recovery codes for your account",
                "New recovery codes have been created for your account. All previous codes are \
                no longer valid.",
                "If you did not do this yourself, contact your administrator immediately.",
            ),
        };
        Self { head, row_1, row_2 }
    }

    pub fn locked(lang: &Language) -> Self {
        let (head, row_1, row_2) = match lang {
            Language::De => (
                "Wiederherstellung vorübergehend gesperrt",
                "Für Ihr Konto wurden mehrfach ungültige Wiederherstellungscodes eingegeben. Die \
                Wiederherstellung ist für bis zu 24 Stunden gesperrt; die Anmeldung mit Passkey \
                funktioniert weiter.",
                "Wenn Sie das nicht selbst waren, wenden Sie sich bitte an Ihre Administration.",
            ),
            _ => (
                "Recovery temporarily locked",
                "Invalid recovery codes have been entered several times for your account. \
                Recovery is locked for up to 24 hours; signing in with a passkey still works.",
                "If this was not you, please contact your administrator.",
            ),
        };
        Self { head, row_1, row_2 }
    }
}
