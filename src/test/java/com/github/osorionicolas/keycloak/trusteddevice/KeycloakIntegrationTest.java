package com.github.osorionicolas.keycloak.trusteddevice;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.token.TokenService;
import org.keycloak.representations.AccessTokenResponse;
import org.testcontainers.containers.output.ToStringConsumer;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class KeycloakIntegrationTest {

    public static final String TEST_REALM = "acme-internal";

    public static final String TEST_CLIENT = "test-client";

    public static final String TEST_USER_PASSWORD = "test";

    public static final KeycloakEnvironment KEYCLOAK_ENVIRONMENT = new KeycloakEnvironment();

    @BeforeAll
    public static void beforeAll() {
        KEYCLOAK_ENVIRONMENT.start();
    }

    @AfterAll
    public static void afterAll() {
        KEYCLOAK_ENVIRONMENT.stop();
    }

    @Test
    public void auditListenerShouldPrintLogMessage() throws Exception {

        Assumptions.assumeTrue(KEYCLOAK_ENVIRONMENT.getMode() == KeycloakEnvironment.Mode.TESTCONTAINERS);

        ToStringConsumer consumer = new ToStringConsumer();
        KEYCLOAK_ENVIRONMENT.getKeycloak().followOutput(consumer);

        TokenService tokenService = KEYCLOAK_ENVIRONMENT.getTokenService();

        // trigger user login via ROPC
        tokenService.grantToken(TEST_REALM, new Form()
                .param("grant_type", "password")
                .param("username", "tester")
                .param("password", TEST_USER_PASSWORD)
                .param("client_id", TEST_CLIENT)
                .param("scope", "openid acme.profile acme.ageinfo")
                .asMap());

        // Allow the container log to flush
        TimeUnit.MILLISECONDS.sleep(750);

        assertThat(consumer.toUtf8String()).contains("audit userEvent");
    }

    @Test
    public void pingResourceShouldBeAccessibleForUser() {

        TokenService tokenService = KEYCLOAK_ENVIRONMENT.getTokenService();

        AccessTokenResponse accessTokenResponse = tokenService.grantToken(TEST_REALM, new Form()
                .param("grant_type", "password")
                .param("username", "tester")
                .param("password", TEST_USER_PASSWORD)
                .param("client_id", TEST_CLIENT)
                .param("scope", "openid")
                .asMap());

        String accessToken = accessTokenResponse.getToken();
        System.out.println("Token: " + accessToken);

        CustomResources customResources = KEYCLOAK_ENVIRONMENT.getClientProxy(CustomResources.class);
        Map<String, Object> response = customResources.ping(TEST_REALM, "Bearer " + accessToken);
        System.out.println(response);

        assertThat(response).isNotNull();
        assertThat(response.get("user")).isEqualTo("tester");
    }


    interface CustomResources {

        @GET
        @Consumes(MediaType.APPLICATION_JSON)
        @jakarta.ws.rs.Path("/realms/{realm}/custom-resources/ping")
        Map<String, Object> ping(@PathParam("realm") String realm, @HeaderParam("Authorization") String token);
    }
}
