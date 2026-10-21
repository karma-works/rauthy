use crate::language::Language;

/// Texts for the E-Mails about registered shared devices. German and English, other languages
/// fall back to English. `{device}`, `{practice}` and `{ip}` are replaced.
#[derive(Debug, PartialEq)]
pub struct I18nSharedDeviceNotification {
    pub head: &'static str,
    pub row_1: &'static str,
    pub row_2: &'static str,
}

impl I18nSharedDeviceNotification {
    pub fn locked(lang: &Language) -> Self {
        let (head, row_1, row_2) = match lang {
            Language::De => (
                "Praxis-PC gesperrt",
                "Der Praxis-PC „{device}“ ({practice}) wurde nach mehreren falschen PINs \
                gesperrt.",
                "Eine Person der Praxis entsperrt ihn, indem sie sich am PC mit ihrem Passkey \
                anmeldet. Wenn niemand aus der Praxis die PINs eingegeben hat, prüfen Sie bitte, \
                wer Zugang zu dem PC hatte.",
            ),
            _ => (
                "Practice PC locked",
                "The practice PC \"{device}\" ({practice}) has been locked after several wrong \
                PINs.",
                "A person of the practice unlocks it by signing in on the PC with their passkey. \
                If nobody of the practice entered the PINs, please check who had access to the \
                PC.",
            ),
        };
        Self { head, row_1, row_2 }
    }

    pub fn ip_changed(lang: &Language) -> Self {
        let (head, row_1, row_2) = match lang {
            Language::De => (
                "Praxis-PC in einem anderen Netz",
                "Am Praxis-PC „{device}“ ({practice}) wurde eine Anmeldung aus einem anderen Netz \
                als bei der Registrierung versucht (IP {ip}).",
                "Das kann nach einem Wechsel des Internetanschlusses normal sein. Wenn der PC die \
                Praxis nicht verlassen hat, prüfen Sie ihn bitte und widerrufen Sie ihn \
                gegebenenfalls in der Praxis-App.",
            ),
            _ => (
                "Practice PC in another network",
                "A sign-in on the practice PC \"{device}\" ({practice}) came from another network \
                than at the registration (IP {ip}).",
                "This can be normal after a change of the internet connection. If the PC has not \
                left the practice, please check it and revoke it in the practice application if \
                necessary.",
            ),
        };
        Self { head, row_1, row_2 }
    }
}
