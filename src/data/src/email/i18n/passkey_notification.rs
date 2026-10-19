use crate::language::Language;

/// Texts for the E-Mails a user gets when a passkey was added to or removed from the account.
/// `{name}` in `row_1` is replaced with the name of the passkey.
#[derive(Debug, PartialEq)]
pub struct I18nPasskeyNotification {
    pub head: &'static str,
    pub row_1: &'static str,
    pub row_2: &'static str,
}

impl I18nPasskeyNotification {
    pub fn added(lang: &Language) -> Self {
        let (head, row_1, row_2) = match lang {
            Language::De => (
                "Neuer Passkey für Ihr Konto",
                "Der Passkey '{name}' wurde Ihrem Konto hinzugefügt.",
                "Wenn Sie das nicht selbst waren, wenden Sie sich bitte sofort an Ihre \
                Administration.",
            ),
            Language::En => (
                "New passkey added to your account",
                "The passkey '{name}' was added to your account.",
                "If you did not add it yourself, contact your administrator immediately.",
            ),
            Language::Fr => (
                "Nouvelle clé d'accès ajoutée à votre compte",
                "La clé d'accès '{name}' a été ajoutée à votre compte.",
                "Si vous ne l'avez pas ajoutée vous-même, contactez immédiatement votre \
                administrateur.",
            ),
            Language::Ja => (
                "アカウントに新しいパスキーが追加されました",
                "パスキー '{name}' がアカウントに追加されました。",
                "ご自身で追加していない場合は、すぐに管理者に連絡してください。",
            ),
            Language::Ko => (
                "계정에 새 패스키가 추가되었습니다",
                "패스키 '{name}'이(가) 계정에 추가되었습니다.",
                "직접 추가하지 않았다면 즉시 관리자에게 문의하세요.",
            ),
            Language::Nb => (
                "Ny passkey lagt til kontoen din",
                "Passkey '{name}' ble lagt til kontoen din.",
                "Hvis du ikke la den til selv, kontakt administratoren din umiddelbart.",
            ),
            Language::Nl => (
                "Nieuwe passkey toegevoegd aan je account",
                "De passkey '{name}' is aan je account toegevoegd.",
                "Heb je deze niet zelf toegevoegd, neem dan direct contact op met je beheerder.",
            ),
            Language::Ru => (
                "В ваш аккаунт добавлен новый ключ доступа",
                "Ключ доступа '{name}' был добавлен в ваш аккаунт.",
                "Если вы не добавляли его сами, немедленно свяжитесь с администратором.",
            ),
            Language::Uk => (
                "До вашого облікового запису додано новий ключ доступу",
                "Ключ доступу '{name}' було додано до вашого облікового запису.",
                "Якщо ви не додавали його самі, негайно зверніться до адміністратора.",
            ),
            Language::ZhHans => (
                "您的账户已添加新的通行密钥",
                "通行密钥 '{name}' 已添加到您的账户。",
                "如果这不是您本人操作，请立即联系您的管理员。",
            ),
        };
        Self { head, row_1, row_2 }
    }

    pub fn removed(lang: &Language) -> Self {
        let (head, row_1, row_2) = match lang {
            Language::De => (
                "Passkey aus Ihrem Konto entfernt",
                "Der Passkey '{name}' wurde von Ihrer Administration entfernt.",
                "Wenn Sie damit nicht gerechnet haben, wenden Sie sich bitte sofort an Ihre \
                Administration.",
            ),
            Language::En => (
                "Passkey removed from your account",
                "The passkey '{name}' was removed by an administrator.",
                "If you did not expect this change, contact your administrator immediately.",
            ),
            Language::Fr => (
                "Clé d'accès supprimée de votre compte",
                "La clé d'accès '{name}' a été supprimée par un administrateur.",
                "Si vous ne vous attendiez pas à ce changement, contactez immédiatement votre \
                administrateur.",
            ),
            Language::Ja => (
                "アカウントからパスキーが削除されました",
                "パスキー '{name}' が管理者によって削除されました。",
                "心当たりがない場合は、すぐに管理者に連絡してください。",
            ),
            Language::Ko => (
                "계정에서 패스키가 삭제되었습니다",
                "패스키 '{name}'이(가) 관리자에 의해 삭제되었습니다.",
                "예상하지 못한 변경이라면 즉시 관리자에게 문의하세요.",
            ),
            Language::Nb => (
                "Passkey fjernet fra kontoen din",
                "Passkey '{name}' ble fjernet av en administrator.",
                "Hvis du ikke forventet denne endringen, kontakt administratoren din umiddelbart.",
            ),
            Language::Nl => (
                "Passkey verwijderd uit je account",
                "De passkey '{name}' is verwijderd door een beheerder.",
                "Had je deze wijziging niet verwacht, neem dan direct contact op met je beheerder.",
            ),
            Language::Ru => (
                "Ключ доступа удалён из вашего аккаунта",
                "Ключ доступа '{name}' был удалён администратором.",
                "Если вы не ожидали этого изменения, немедленно свяжитесь с администратором.",
            ),
            Language::Uk => (
                "Ключ доступу видалено з вашого облікового запису",
                "Ключ доступу '{name}' було видалено адміністратором.",
                "Якщо ви не очікували цієї зміни, негайно зверніться до адміністратора.",
            ),
            Language::ZhHans => (
                "您的账户中的通行密钥已被移除",
                "通行密钥 '{name}' 已被管理员移除。",
                "如果您没有预料到此更改，请立即联系您的管理员。",
            ),
        };
        Self { head, row_1, row_2 }
    }
}
