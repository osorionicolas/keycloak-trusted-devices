package com.github.osorionicolas.keycloak.trusteddevice.support;

import org.keycloak.models.RealmModel;

public class RealmUtils {

    public static String getDisplayName(RealmModel realm) {

        var displayName = realm.getDisplayName();
        if (displayName == null) {
            displayName = realm.getName();
        }

        return displayName;
    }
}
