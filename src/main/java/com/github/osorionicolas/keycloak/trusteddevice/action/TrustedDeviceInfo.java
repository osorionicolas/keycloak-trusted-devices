package com.github.osorionicolas.keycloak.trusteddevice.action;

public class TrustedDeviceInfo {

    private final String deviceName;

    public TrustedDeviceInfo(String deviceName) {
        this.deviceName = deviceName;
    }

    public String getDeviceName() {
        return deviceName;
    }
}
