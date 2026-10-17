import type { PasswordPolicyResponse } from '$api/types/password_policy';

export interface PasswordResetTemplate {
    csrf_token: string;
    magic_link_id: string;
    needs_mfa: boolean;
    // `true` if only a passkey can be registered (`webauthn.new_user_passkey_only`)
    passkey_only: boolean;
    password_policy: PasswordPolicyResponse;
    user_id: string;
}
