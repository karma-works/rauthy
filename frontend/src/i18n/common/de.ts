import { type I18n } from './interface';

export const I18nDe: I18n = {
    lang: 'de',
    common: {
        accept: 'Akzeptieren',
        activeTheme: 'Aktives Farbschema',
        authenticate: 'Authentifizieren',
        cancel: 'Abbrechen',
        changeTheme: 'Farbschema wechseln - Aktiv: {{ CURRENT }}',
        close: 'Schließen',
        copyToClip: 'Wert in Zwischenablage kopieren',
        delete: 'Löschen',
        details: 'Details',
        edit: 'Bearbeiten',
        email: 'E-Mail',
        errTooShort: 'Eingabe zu kurz',
        errTooLong: 'Eingabe zu lang',
        expandContent: 'Inhalt ausklappen',
        hide: 'Verbergen',
        hours: 'Stunden',
        invalidInput: 'Ungültige Eingabe',
        legend: 'Legende',
        maxFileSize: 'Maximale Dateigröße',
        minutes: 'Minuten',
        month: 'Monat',
        months: [
            'Januar',
            'Februar',
            'März',
            'April',
            'Mai',
            'Juni',
            'Juli',
            'August',
            'September',
            'Oktober',
            'November',
            'Dezember',
        ],
        never: 'Niemals',
        password: 'Passwort',
        refresh: 'Erneuern',
        required: 'Notwendig',
        save: 'Speichern',
        search: 'Suchen',
        seconds: 'Sekunden',
        selectI18n: 'Sprache wählen',
        show: 'Anzeigen',
        summary: 'Zusammenfassung',
        timezone: 'Zeitzone',
        weekDaysShort: ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So'],
        year: 'Jahr',
    },
    account: {
        account: 'Benutzer Account',
        accType: 'Account Typ',
        accTypePasskeyText1: `Dies ist ein "Passkey-Only" Account. Das bedeutet, dass\ndieser 
            Account kein Passwort hat und auch keines benötigt.`,
        accTypePasskeyText2: `Der Account kann in einen Passwort-Account umgewandelt\nwerden. Das 
            würde allerdings bedeuten, dass ein Login auf einem neuen Gerät ohne vorherige, 
            zumindest\neinmalige zusätzliche Verifizierung des Passwortes nicht mehr möglich sein 
            wird.`,
        accTypePasskeyText3: 'Soll dieser Account gewandelt und ein Passwort hinzugefügt werden?',
        accessExp: 'Zugang erlischt',
        accessRenew: 'Zugang erneuerbar bis',
        accessRenewDelete: 'Möglichkeit zur Erneuerung löschen',
        birthdate: 'Geburtsdatum',
        canModifyFor: 'MFA können modifiziert werden für:',
        city: 'Stadt',
        changePassword: 'Passwort wechseln',
        convertAccount: 'Account Umwandeln',
        convertAccountP1: `Dieser Account kann in einen Passkey-Only Account umgewandelt\nwerden. 
            Diese Umwandling löscht das Passwort und erlaubt den alleinigen Login mit den 
            registrieren\nPasskeys. Nur Passkeys mit zusätzlicher Benutzerverifizierung werden 
            akzeptiert. Diese sind auf der\n'MFA' Seite durch das zusätzliche Symbol hinter dem 
            Passkey Namen gekennzeichnet.`,
        country: 'Land',
        deleteAccount: {
            deleteAccount: 'Account Löschen',
            deleteAccountDesc: `ACHTUNG: Das Löschen dieses Accounts ist unwiderruflich! Zur 
            Bestätigung, bitte eingeben:`,
        },
        deviceId: 'ID',
        deviceName: 'Name',
        devices: 'Geräte',
        devicesDesc: 'Mit diesem Account verknüpfte Geräte',
        emailUpdateConfirm: `Die E-Mail Adresse wurde noch nicht aktualisiert. Eine Nachricht\nmit 
            einem Bestätigungslink wurde an die neue Adresse geschickt. Das Update muss über den
            \nenthaltenen Link bestätigt werden. Nach der Bestätigung wird die neue Adresse gesetzt.`,
        emailVerified: 'E-Mail verifiziert',
        familyName: 'Nachname',
        federatedConvertPassword1: `Dies ist ein verknüpfter Account. Das bedeutet, dass\nder 
            Login via externem Provider zur Authenzifizierung geschieht. Der derzeitige Provider 
            ist:`,
        federatedConvertPassword2: `Es kann ein Passwort Reset via E-Mail angefordert\nwerden. Das 
            würde nach Abschluss diesem Account ein lokales Passwort hinzufügen. Danach wäre der\n
            Login entweder per externem Provider oder lokalem Password möglich. Passwort Reset 
            anfordern?`,
        generateRandom: 'Zufällig generiert',
        givenName: 'Vorname',
        groups: 'Gruppen',
        key: 'Schlüssel',
        keyUnique: 'Schlüssel muss einzigartig sein',
        lastLogin: 'Letzter Login',
        mfaActivated: 'MFA aktiviert',
        navInfo: 'Info',
        navEdit: 'Editieren',
        navMfa: 'MFA',
        navLogout: 'Logout',
        navBackToAdmin: 'Admin-UI',
        other: 'Sonstiges',
        pam: {
            addSshKey: 'Neuen Key Hinzufügen',
            comment: 'Kommentar',
            generatePassword: 'Neues Passwort',
            keyAdded: 'Hinzugefügt',
            keyType: 'Typ',
            username: 'Benutzername',
            validFor: 'Passwort gültig für {{ secs }} Sekunden',
        },
        passkeys: {
            missingAttestation:
                'Der Passkey entspricht nicht den geforderten Sicherheitsstandards.',
            type: 'Passkey Typ',
            types: ['Normal', 'Verknüpft'],
            rkWarning: `ACHTUNG: Ein verknüpfter Passkey (Resident Key) kann zwar zum direkten Login 
                ohne die Eingabe der E-Mail Addresse genutzt werden, aber es wird auch ein 
                zusätzlicher Speicherplatz für jede Anwendung gebraucht. Es muss dafür gesorgt 
                werden, dass genug Speicher vorhanden ist.
                Um einen bestehenden Passkey zu einem verknüpften zu machen, muss er zuerst
                gelöscht und dann neu hinzugefügt werden.`,
            // [Default, Resident Key]
            typesDesc: [
                'Vor dem Login mit diesem Passkey muss die E-Mail Adresse eingegeben werden.',
                `Funktioniert mit dem Passkey Button auf der Login Seite, ohne Eingabe der
                    E-Mail Adresse.`,
            ],
        },
        passwordConfirm: 'Passwort bestätigen',
        passwordCurr: 'Derzeitiges Passwort',
        passwordCurrReq: 'Derzeitiges Passwort ist notwendig',
        passwordNew: 'Neues Passwort',
        passwordNewReq: 'Neues Passwort ist notwendig',
        passwordNoMatch: 'Passwörter stimmen nicht überein',
        passwordExpiry: 'Passwort Ablauf',
        passwordPolicyFollow: 'Befolgen Sie die Passwort Regeln',
        passwordReset: 'Passwort Reset',
        phone: 'Telefon',
        preferredUsername: {
            desc: `Manche Anwendungen greifen auf diesen Benutzernamen zurück. Welche 
				Anwendung davon gebraucht macht, kann allerdings nicht kontrolliert werden.`,
            forceOverwrite: 'Überschreiben Erzwingen',
            immutable: 'ACHTUNG: Der Benutzername kann nur einmalig gesetzt werden!',
            immutableInfo: 'Der Benutzername kann nicht geändert werden.',
            notAvailable: 'Dieser Name ist nicht verfügbar.',
            preferredUsername: 'Bevorzugter Benutzername',
        },
        providerLink: 'Account Verbinden',
        providerLinkDesc: `Dieser Account kann mit einem der folgenden Login Provider\nverbunden 
            werden. Nach der Aktivierung des Prozesses wird eine Weiterleitung auf die Login Seite\n
            des gewählten Providers ausgelöst. Nach erfolgreichem Login und bei Übereinstimmung der 
            E-Mail\nAdressen wird dieser Account verknüpft.`,
        providerUnlink: 'Verbindung Trennen',
        providerUnlinkDesc: `Nur wenn mindestens ein Passwort oder ein Passkey für diesen\nAccount 
            gesetzt ist, kann die Verbindung zum Provider gelöst werden.`,
        regDate: 'Datum der Registrierung',
        regIp: 'Registrierung von IP',
        roles: 'Rollen',
        street: 'Straße',
        user: 'Benutzer',
        userCreated: 'Benutzer erstellt',
        userEnabled: 'Benutzer Aktiviert',
        userExpiry: 'Benutzer Ablauf',
        userVerifiedTooltip: 'Abgesichert durch Fingerabdruck oder PIN',
        residentKeyTooltip: `Dies ist ein Resident Key. Er kann für direkten Login ohne Eingabe der E-Mail verwendet 
            werden.`,
        aaguidTooltip: 'Zertifizierter Passkey',
        webIdDesc: `Hier können Sie die Felder festlegen, die über Ihre WebID veröffentlicht\n
            werden. Dies ist ein Feature, was von manchen Netzwerken für dezentrale Logins genutzt 
            wird.\nSollten Sie nicht wissen, was die WebID ist, brauchen Sie sie 
            höchstwahrscheinlich nicht.`,
        webIdDescData:
            'Sie können eigene Daten zu Ihrer WebID in gültigem FOAF Vokabular\nhinzufügen:',
        webIdExpertMode: 'Expertenmodus aktivieren',
        zip: 'PLZ',
    },
    authorize: {
        clientForceMfa: `Dieser Login setzt MFA voraus für eine erhöhte Sicherheit.\nUm Zugang zu 
            bekommen, müssen Sie sie in Ihren Account einloggen und mindestens einen Passkey\n
            hinzufügen.`,
        clientGroupPrefixForbidden: 'Fehlende Gruppenzugehörigkeit für diesen Login',
        email: 'E-Mail',
        emailBadFormat: 'Inkorrektes E-Mail Format',
        emailRequired: 'E-Mail ist notwendig',
        emailSentMsg: 'Sollte Ihre Adresse registriert sein, wurde eine Nachricht versandt',
        expectingPasskey: 'Erwarte Authentifizierung per Passkey',
        expectingOtp: 'Erwarte Authentifizierung per Einmalpasswort',
        http429: 'Zu viele ungültige Versuche. Gesperrt bis:',
        invalidCredentials: 'Ungültige Zugangsdaten',
        invalidKeyUsed: 'Ungültiger Sicherheitsschlüssel',
        login: 'Login',
        mfaAck: 'Bestätigt',
        navigateToAccount: 'Account Dashboard',
        needsUserUpdate: `Es fehlen Informationen zum Account. Diese benötigen ein Update, bevor
            mit dem Login fortgefahren werden kann.`,
        orLoginWith: 'oder einloggen mit',
        passkeyNotDiscovered: `Passkeys, die nicht verknüpft (als Resident Key) hinzugefügt wurden,
            können so nicht gefunden werden. Bitte stattdessen die E-Mail Adresse eingeben.`,
        password: 'Password',
        passwordExpired:
            'Passwort ist abgelaufen. Eine E-Mail mit einem Reset-Link wurde verschickt.',
        passwordForgotten: 'Password vergessen?',
        passwordRequest: 'Anfordern',
        passwordRequired: 'Password ist notwendig',
        passwordResetDesc: `Bitte E-Mail Adresse angeben, um einen Password Reset Link anzufordern. 
            Sollte die Adresse in der Datenbank existieren, wird and diese ein Link verschickt.`,
        passwordResetSuccess: 'Anfrage erhalten. Dieses Fenster kann nun geschlossen werden.',
        requestExpires: 'Anfrage läuft ab',
        requestExpired: 'Anfrage ist abgelaufen',
        signUp: 'Benutzer Registrierung',
        validEmail: 'Gültige E-Mail Adresse angeben',
    },
    device: {
        accept: 'Akzeptieren',
        autoRedirectAccount: 'Automatische Weiterleitung zum Account folgt',
        closeWindow: 'Dieses Fenster kann nun geschlossen werden.',
        decline: 'Ablehnen',
        desc: 'Bitte den {{count}}-stelligen vom Gerät angezeigten Benutzer Code eingeben.',
        descScopes: 'Das Gerät fragt Zugang an zu:',
        isAccepted: 'Die Anfrage wurde akzeptiert',
        isDeclined: 'Die Anfrage wurde abgewiesen',
        submit: 'Absenden',
        title: 'Gerät Authorisierung',
        userCode: 'Benutzer Code',
        wrongOrExpired: 'Ungültiger oder abgelaufener Code',
    },
    emailChange: {
        title: 'E-Mail Wechsel bestätigt',
        textChanged: 'Ihre E-Mail Adresse wurde erfolgreich geändert von',
        textLogin: 'Sie können sich jetzt mit der neuen Adresse einloggen.',
        to: 'zu',
    },
    error: {
        // errorText: "Die angeforderte Seite konnte nicht gefunden werden.",
        details: 'Details Anzeigen',
        // detailsText: undefined,
    },
    index: {
        register: 'Registrieren',
        accountLogin: 'Account',
        adminLogin: 'Admin',
    },
    legal: {
        imprint: 'Impressum',
        privacy: 'Datenschutz',
        help: 'Hilfe',
    },
    recoveryCodes: {
        title: 'Ihre Wiederherstellungscodes',
        desc: 'Bewahren Sie die Codes getrennt von Ihren Geräten auf, zum Beispiel ausgedruckt an einem sicheren Ort. Jeder Code funktioniert genau einmal.',
        copy: 'Kopieren',
        copied: 'Kopiert',
        download: 'Als Textdatei',
        print: 'Drucken',
        warning:
            'Ein Code allein öffnet Ihr Konto nicht. Er erlaubt nur, nach einer Bestätigung per E-Mail einen neuen Passkey einzurichten. Speichern Sie die Datei nicht auf einem gemeinsam genutzten Computer.',
        confirm: 'Ich habe die Codes sicher aufbewahrt',
        done: 'Fertig',
        fileTitle: 'Wiederherstellungscodes – jeder Code gilt genau einmal',
    },
    recover: {
        title: 'Passkey verloren?',
        desc: 'Geben Sie Ihre E-Mail-Adresse und einen Ihrer Wiederherstellungscodes ein. Danach bestätigen Sie mit einem Code aus einer E-Mail und richten einen neuen Passkey ein.',
        code: 'Wiederherstellungscode',
        codePlaceholder: 'ABCD-EFGH-JKLM',
        continue: 'Weiter',
        mailSent:
            'Wenn E-Mail-Adresse und Code stimmen, haben wir Ihnen einen Bestätigungscode geschickt. Er gilt 10 Minuten.',
        mailCode: 'Bestätigungscode aus der E-Mail',
        confirm: 'Bestätigen',
        invalidMailCode: 'Der Code ist ungültig oder abgelaufen.',
        restart: 'Neu beginnen',
        newPasskey: 'Richten Sie jetzt einen neuen Passkey ein.',
        done: 'Ihr neuer Passkey ist eingerichtet. Alle bisherigen Anmeldungen wurden beendet. Melden Sie sich jetzt neu an, entfernen Sie den verlorenen Passkey in Ihrem Konto und erzeugen Sie neue Wiederherstellungscodes.',
        toAccount: 'Zum Konto',
        noCodes: 'Keine Codes zur Hand? Wenden Sie sich an Ihre Administration.',
    },
    splitLogin: {
        title: 'Anmelden bei {client}',
        intro: 'Wählen Sie den Weg, der zu Ihrer Situation passt.',
        existingTag: 'Login an bestehendem Gerät',
        existingTitle: 'Ich habe mich hier schon angemeldet',
        existingDesc:
            'Auf diesem Computer oder Smartphone ist bereits ein Passkey gespeichert. Ein Klick genügt, danach bestätigen Sie mit Fingerabdruck, Gesicht oder PIN.',
        existingButton: 'Mit Passkey anmelden',
        existingNotFound:
            'Auf diesem Gerät wurde kein Passkey gefunden. Nutzen Sie „Neulogin“ mit Ihrem Smartphone oder Sicherheitsschlüssel.',
        newTag: 'Neulogin',
        newTitle: 'Erstes Mal hier oder anderes Gerät',
        newDesc:
            'Geben Sie Ihre E-Mail-Adresse ein. Danach bestätigen Sie mit Ihrem Smartphone oder Sicherheitsschlüssel.',
        emailPlaceholder: 'name@beispiel.de',
        continue: 'Weiter',
        or: 'oder',
        lost: 'Passkey verloren? Wenden Sie sich an Ihre Administration.',
        wrongAccount:
            'Anmeldung nicht möglich. Prüfen Sie die E-Mail-Adresse und verwenden Sie einen Passkey dieses Kontos.',
        lostPrefix: 'Passkey verloren?',
        lostLink: 'Mit Wiederherstellungscode fortfahren',
        lostSuffix: 'oder an Ihre Administration wenden.',
    },
    passkeyDevice: {
        kind: 'Gerät',
        kindInternal: 'Dieser Computer',
        kindHybrid: 'Smartphone',
        kindSecurityKey: 'Sicherheitsschlüssel',
    },
    sharedDevice: {
        pinTitle: 'Anmelden mit PIN',
        pinLabel: 'PIN',
        pinHint: 'Ihr vierstelliger PIN für die PCs dieser Praxis',
        pinSubmit: 'Anmelden',
        pinFormat: 'Der PIN hat vier Ziffern.',
        wrongPin: 'PIN falsch. Noch {n} falsche PINs heute, dann wird der PC gesperrt.',
        locked: 'Dieser PC ist nach zu vielen falschen PINs gesperrt. Eine Person der Praxis entsperrt ihn, indem sie sich hier mit ihrem Passkey anmeldet.',
        unlock: 'Mit Passkey entsperren',
        invalidDevice:
            'Dieser PC ist nicht mehr als Praxis-PC registriert. Bitte melden Sie sich mit Ihrem Passkey an.',
        forbidden:
            'Eine Anmeldung mit PIN ist hier nicht möglich, zum Beispiel außerhalb des Praxisnetzes. Bitte melden Sie sich mit Ihrem Passkey an.',
        usePasskey: 'Mit Passkey anmelden',
        passkeyNeeded: 'Für diese Anmeldung ist Ihr Passkey nötig.',
        registerTitle: 'Praxis-PC registrieren',
        registerDesc:
            'Dieser Browser wird als gemeinsamer Praxis-PC „{label}“ für {practice} registriert. Danach melden sich Personen der Praxis hier mit ihrem PIN an.',
        riskTitle: 'Hinweis zum Restrisiko',
        riskText:
            'An einem Praxis-PC genügt ein vierstelliger PIN für die tägliche Arbeit. Stellen Sie Praxis-PCs nur in Räumen auf, die Unbefugte nicht betreten können, und halten Sie PINs geheim. Für kritische Aktionen bleibt der Passkey nötig.',
        riskAck: 'Ich habe den Hinweis gelesen und bestätige ihn für die Praxis.',
        riskRequired: 'Bitte bestätigen Sie den Hinweis.',
        registerSubmit: 'Mit Passkey bestätigen und registrieren',
        registerDone:
            'Dieser PC ist jetzt als Praxis-PC registriert. Sie wurden in diesem Browser abgemeldet.',
        backToApp: 'Zurück zur Anwendung',
        registerNotFound:
            'Die Registrierung ist abgelaufen oder gehört zu einem anderen Konto. Bitte starten Sie sie in der Anwendung neu.',
        registerNoSession:
            'Bitte melden Sie sich zuerst in diesem Browser in der Anwendung an und starten Sie die Registrierung dort.',
        registerUnsupported:
            'Dieser Browser kann keinen Geräteschlüssel speichern. Bitte verwenden Sie einen aktuellen Browser.',
        registerErr: 'Der PC konnte nicht registriert werden.',
        pinsTitle: 'PIN für Praxis-PCs',
        pinsDesc:
            'Mit dem PIN melden Sie sich an den registrierten PCs Ihrer Praxis an. Ein neuer PIN wird nur einmal angezeigt.',
        pinNone: 'Noch kein PIN',
        pinCreated: 'PIN vom {date}',
        pinCreate: 'PIN erzeugen',
        pinNew: 'Neuer PIN',
        pinShow: 'Ihr neuer PIN für {practice}:',
        pinShowHint:
            'Merken Sie sich den PIN jetzt, er wird nicht wieder angezeigt. Ein bisheriger PIN gilt nicht mehr.',
        pinDone: 'Fertig',
        pinErr: 'Der PIN konnte nicht erzeugt werden.',
        pinTooMany: 'Zu viele neue PINs heute. Bitte versuchen Sie es morgen wieder.',
    },
    logout: {
        logout: 'Logout',
        confirmMsg: 'Sind Sie sicher, dass Sie sich ausloggen und die Session beenden möchten?',
        cancel: 'Abbrechen',
    },
    mfa: {
        webauthn: {
            title: 'Passkeys',
            p1: `Wenn Sie mehrere Systeme parallel nutzen möchten, wie z.B. Windows und Android, 
                sollten Sie die Registrierung mit Android durchführen.`,
            p2: `Android ist diejenige Plattform, die derzeit die wenigsten Features der passwortlosen 
                Technologie unterstützt. Schlüssel, die dort registriert werden, funktionieren auf 
                anderen Geräten gleichermaßen. Dies gilt jedoch nicht andersherum.`,
            p3: 'Für weitere Informationen, siehe',
            registerNew: 'Neuen Passkey Registrieren',
            addFlowHint:
                'Zuerst bestätigen Sie mit Ihrem vorhandenen Passkey, dann legen Sie den neuen an.',
            onlyOneHint:
                'Richten Sie einen zweiten Passkey ein, z. B. auf Ihrem Smartphone. Fällt ein Gerät aus, kommen Sie so weiter an Ihr Konto.',
            docLinkText: 'die Dokumentation zu Passkeys',
            unsupportedText: 'Dieser Browser ist zu alt und unterstützt kein Webauthn.',
        },
        otp: {
            title: 'Einmalpasswort',
            titleEmail: 'Email-basierte Einmalpasswörter',
            activationCode: 'Bitte gib das per E-Mail gesendete Einmalpasswort ein.',
            code: 'Einmalpasswort',
            registerNew: 'Neuen OTP Registrieren',
            resendOtp: 'Neues Einmalpasswort Senden',
            sessionExpiresIn: 'Einmalpasswort läuft ab in:',
            sessionExpired: 'Einmalpasswort abgelaufen',
        },
        requestCanceled: 'Anfrage abgebrochen',
        errorReg: 'Fehler beim Starten der Registrierung',
        lastUsed: 'Zuletzt genutzt',
        noKey: 'Es wurde in diesem Speicher noch kein Sicherheitsschlüssel registriert',
        reAuthenticatePasskey: `Bevor Passkeys bearbeitet werden können, muss zuerst einer der 
            bestehenden überprüft werden:`,
        reAuthenticatePwd: `Bevor Passkeys bearbeitet werden können, ist eine erneute Bestätigung 
            des Passworts notwendig.`,
        reAuthenticateOtp: `Bevor Einmalpasswort bearbeitet werden können, muss zuerst einer der 
            bestehenden überprüft werden:`,
        register: 'Registrieren',
        registered: 'Registriert',
        registeredKeys: 'Registrierte Passkeys',
        registeredOtps: 'Registrierte Einmalpasswörter',
        passkeyName: 'Passkey Name',
        passkeyNameErr: '2 - 32 Buchstaben, keine Sonderzeichen',
        passwordInvalid: 'Ungültiges Password',
        test: 'Test',
        testError: 'Fehler beim Starten des Tests',
        testSuccess: 'Test erfolgreich',
    },
    pagination: {
        entries: 'Einträge',
        gotoPage: 'Gehe zu Seite',
        gotoPagePrev: 'Gehe zu vorheriger Seite',
        gotoPageNext: 'Gehe zu nächster Seite',
        pagination: 'Seitennummerierung',
        showCount: 'Anzahl anzeigen',
        total: 'Gesamt',
    },
    passwordPolicy: {
        passwordPolicy: 'Passwort Regeln',
        lengthMin: 'Länge min',
        lengthMax: 'Länge max',
        lowercaseMin: 'Kleinbuchstaben min',
        uppercaseMin: 'Großbuchstaben min',
        digitsMin: 'Ziffern min',
        specialMin: 'Spezielle Buchstaben min',
        notRecent: 'Keins der letzten Passwörter',
    },
    passwordReset: {
        accountLogin: 'Account Login',
        badFormat: 'Ungültiges Format',
        fidoLink: 'https://fidoalliance.org/fido2',
        generate: 'Generieren',
        newAccDesc1: `Sie haben die Option zwischen zwei Account Typen zu wählen: Passwortlos 
            oder\ntraditionalles Passwort.`,
        newAccDesc2: `Der passwortlose Account Typ ist immer zu bevorzugen. Er bietet einen\nsehr 
            viel höheren Sicherheitsstandard als traditionelle Passwörter und gleichzeitig einen 
            einfacheren\nund schnelleren Login.\nDazu wird mindestens ein Passkey (Yubikey, Apple 
            Touch ID, Windows Hello, ...) benötigt, welcher dem\nFIDO2 Standard gerecht wird. Für 
            weitere Informationen können Sie diesem Link folgen: `,
        newAccDescPasskeyOnly:
            'Für Ihr Konto richten Sie einen Passkey ein. Damit melden Sie sich ohne Passwort an, z. B. mit Fingerabdruck, Gesichtserkennung oder der PIN Ihres Geräts.',
        newAccount: 'Neuer Account',
        passwordReset: 'Passwort Zurücksetzen',
        password: 'Passwort',
        passwordless: 'Passkey',
        passwordConfirm: 'Passwort bestätigen',
        passwordNoMatch: 'Passwörter stimmen nicht überein',
        required: 'Notwendig',
        save: 'Speichern',
        success1: 'Das Passwort wurde erfolgreich zurückgesetzt.',
        success2: 'Sie werden in Kürze weitergeleitet.',
        success3: 'Sollte Sie nicht weitergeleitet werden, klicken Sie bitte hier:',
        successPasskey1: 'Der neue Passkey wurde erfolgreich registriert.',
        successPasskey2: `Bitte richten Sie nach der Anmeldung einen zweiten Passkey ein, z. B. auf
            Ihrem Smartphone. Geht Ihr einziger Passkey verloren, können Sie sich sonst nicht mehr
            anmelden.`,
    },
    register: {
        alreadyRegisteredEmail: 'E-Mail is bereits registriert',
        alreadyRegisteredUsername: 'Benutzername is bereits vergeben',
        domainAllowed: 'Erlaubte Domain:',
        domainErr: 'E-Mail Domain ist nicht erlaubt',
        domainRestricted: 'E-Mail Domains sind beschränkt',
        email: 'E-Mail',
        emailBadFormat: 'Ungültiges E-Mail Format',
        emailCheck: 'Bitte prüfen Sie Ihren E-Mail Posteingang',
        orRegisterWith: 'order registrieren mit',
        regexName: 'Name mit 2 - 32 Buchstaben ohne Sonderzeichen',
        register: 'Registrieren',
        success: 'Registrierung erfolgreich',
        userReg: 'Benutzer Registrierung',
    },
    tos: {
        acceptOptUntil: 'Akzeptieren ist optional bis:',
        deny: 'Verweigern',
        tos: 'Allgemeine Geschäftsbedingungen',
    },
    userRevoke: {
        title: 'Logins widerrufen',
        desc1: `Sämtliche Logins und Sessions für diesen Benutzer wurden soweit wie möglich 
            widerrufen.`,
        desc2: 'Passwörter sollten auf der Stelle erneuert werden!',
    },
};
