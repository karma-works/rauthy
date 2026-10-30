/** `<template id="tpl_shared_device">` on the login page of a registered shared device */
export interface SharedDeviceTemplate {
    label: string;
    practice: string;
    locked: boolean;
    /** `false` if this client accepts no PIN, or the request asks for a fresh passkey */
    pin: boolean;
    roles_enabled?: boolean;
}

export interface SharedDeviceChallengeResponse {
    id: string;
    challenge: string;
}

export interface PinLoginRequest {
    role?: string;
    pin: string;
    challenge_id: string;
    signature: string;
    client_id: string;
    redirect_uri: string;
    scopes?: string[];
    state?: string;
    nonce?: string;
    code_challenge?: string;
    code_challenge_method?: string;
    resource?: string;
}

/** `wrong_pin`, `locked`, `invalid_device` */
export interface PinLoginErrorResponse {
    error: string;
    remaining?: number;
}

export interface SharedDeviceRegistrationInfoResponse {
    practice_name: string;
    label: string;
    needs_risk_ack: boolean;
    password_allowed?: boolean;
    return_uri?: string;
    exp: number;
}

export interface SharedDeviceRegisterRequest {
    mfa_mod_token_id?: string;
    password?: string;
    public_key: string;
    signature: string;
    risk_ack: boolean;
}

export interface SharedDeviceRegisterResponse {
    device_id: string;
    return_uri?: string;
}

export interface SharedDevicePinInfoResponse {
    practice_id: string;
    practice_name: string;
    pin_created?: number;
}

export interface SharedDevicePinResponse {
    pin: string;
}
