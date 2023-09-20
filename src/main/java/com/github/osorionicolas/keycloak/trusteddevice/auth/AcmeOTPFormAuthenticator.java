package com.github.osorionicolas.keycloak.trusteddevice.auth;

import com.github.osorionicolas.keycloak.trusteddevice.action.ManageTrustedDeviceAction;
import com.google.auto.service.AutoService;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import jakarta.ws.rs.core.MultivaluedMap;
import java.util.List;

public class AcmeOTPFormAuthenticator extends OTPFormAuthenticator {

    public static final String ID = "acme-auth-otp-form";

    @Override
    public void validateOTP(AuthenticationFlowContext context) {
        super.validateOTP(context);

        if (FlowStatus.SUCCESS.equals(context.getStatus())) {
            MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();
            if (formParams.containsKey("register-trusted-device")) {
                context.getUser().addRequiredAction(ManageTrustedDeviceAction.ID);
            }
        }
    }

    @AutoService(AuthenticatorFactory.class)
    public static class Factory extends OTPFormAuthenticatorFactory {

        public static final AcmeOTPFormAuthenticator SINGLETON = new AcmeOTPFormAuthenticator();

        @Override
        public Authenticator create(KeycloakSession session) {
            return SINGLETON;
        }

        @Override
        public String getId() {
            return AcmeOTPFormAuthenticator.ID;
        }

        @Override
        public String getDisplayType() {
            return "Acme: OTP Form";
        }

        @Override
        public String getHelpText() {
            return "Validates a OTP on a separate OTP form.";
        }

        @Override
        public List<ProviderConfigProperty> getConfigProperties() {
            return null;
        }

        @Override
        public String getReferenceCategory() {
            return OTPCredentialModel.TYPE;
        }

        @Override
        public boolean isUserSetupAllowed() {
            return true;
        }

    }

}
