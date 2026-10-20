export interface PasskeyResponse {
    name: string;
    /// Unix timestamp in seconds
    registered: number;
    /// Unix timestamp in seconds
    last_used: number;
    user_verified?: boolean;
    resident_key?: boolean;
    /// The AAGUID of the authenticator, if it was present in the attestation data.
    /// If it exists, this is an attested device.
    aaguid?: string;
    /// Will be set for an attested device.
    description?: string;
    /// How the passkey has been added, reported by the browser
    kind?: 'internal' | 'hybrid' | 'security_key';
    /// The answer to the "shared computer" question during the registration
    shared_device?: 'yes' | 'no' | 'unknown';
}

export interface WebauthnDeleteRequest {
    /// 32 chars long MfaModToken.id
    mfa_mod_token_id?: string;
}
