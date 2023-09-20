package com.github.osorionicolas.keycloak.trusteddevice.mfa;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class MfaInfo {

    private final String type;
    private final String label;
}
