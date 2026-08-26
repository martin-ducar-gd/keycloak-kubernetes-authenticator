package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.models.ClientModel;

import java.net.URISyntaxException;
import java.util.List;

import static de.chrfritz.keycloak.kubernetes.authenticator.impl.KubernetesClientAuthenticator.PROVIDER_ID;
import static de.chrfritz.keycloak.kubernetes.authenticator.impl.KubernetesClientAuthenticator.TRUSTED_ISSUERS;
import static de.chrfritz.keycloak.kubernetes.authenticator.impl.TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.keycloak.authentication.AuthenticationFlowError.*;
import static org.keycloak.protocol.oidc.OIDCLoginProtocol.LOGIN_PROTOCOL;
import static org.keycloak.protocol.oidc.OIDCLoginProtocol.PRIVATE_KEY_JWT;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for the {@link KubernetesClientAuthenticator}.
 */
@DisplayNameGeneration(ReplaceUnderscores.class)
class KubernetesClientAuthenticatorTest {

    private static final String EXPECTED_AUD = "https://localhost:8080/auth/realms/test-realm";
    private static final String EXPECTED_ISSUER = "http://issuer";
    private static final String EXPECTED_SUBJECT = "system:serviceaccount:dummy:dummy";
    private final KubernetesClientAuthenticator authenticator = new KubernetesClientAuthenticator();

    @Test
    void test_AuthenticateClient_successfully() throws URISyntaxException {
        // given
        ClientModel clientNoDescription = mockClient("dummy", null, true);
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(clientNoDescription, client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context, never()).failure(any(), any());
        verify(context).success();
    }

    @Test
    void test_AuthenticateClient_expired() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -80, -80, -60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(INVALID_CLIENT_CREDENTIALS), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_no_yet_valid() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, 60, 90);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(INVALID_CLIENT_CREDENTIALS), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_different_signing_key_but_same_kid() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60, mockKey("1"));
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(INVALID_CLIENT_CREDENTIALS), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_missing_key_setup() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60, mockKey("2"));
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_CREDENTIALS_SETUP_REQUIRED), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_client_disabled() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", false);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_DISABLED), isNull());
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_wrong_audience() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, "", -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(INVALID_CLIENT_CREDENTIALS), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_unknown_client() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, "http://otherIssuer", EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_NOT_FOUND), isNull());
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_other_client_assertation() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), "other", "dummy");


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).challenge(any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_trusted_issuer_accepts_description_of_the_peer_cluster() throws URISyntaxException {
        // given a description rendered by the other member of the DR pair, naming its issuer
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://peerIssuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);

        // when
        authenticatorTrusting(EXPECTED_ISSUER + "=http://issuer/keys").authenticateClient(context);

        // then
        verify(context, never()).failure(any(), any());
        verify(context).success();
    }

    @Test
    void test_AuthenticateClient_trusted_issuer_still_requires_the_subject_to_match() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:other@http://peerIssuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);

        // when
        authenticatorTrusting(EXPECTED_ISSUER + "=http://issuer/keys").authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_NOT_FOUND), isNull());
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_untrusted_issuer_is_not_accepted_for_a_foreign_description() throws URISyntaxException {
        // given an issuer this instance was not configured to trust
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://peerIssuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);

        // when
        authenticatorTrusting("http://somewhereElse=http://somewhereElse/keys").authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_NOT_FOUND), isNull());
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_accepts_either_issuer_of_a_trusted_pair() throws URISyntaxException {
        // given one client bound to both members of a DR pair, and both issuers trusted
        String peerIssuer = "http://peerIssuer";
        String description = EXPECTED_SUBJECT + "@" + EXPECTED_ISSUER + "\n" + EXPECTED_SUBJECT + "@" + peerIssuer;
        String trusted = EXPECTED_ISSUER + "=http://issuer/keys," + peerIssuer + "=http://peerIssuer/keys";

        for (String issuer : List.of(EXPECTED_ISSUER, peerIssuer)) {
            ClientModel client = mockClient("dummy", description, true);
            String token = mockToken(EXPECTED_SUBJECT, issuer, EXPECTED_AUD, -1, -1, 60);
            ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);

            // when
            authenticatorTrusting(trusted).authenticateClient(context);

            // then
            verify(context, never()).failure(any(), any());
            verify(context).success();
        }
    }

    @Test
    void test_AuthenticateClient_rejects_an_issuer_outside_the_trusted_pair() throws URISyntaxException {
        // given
        String description = EXPECTED_SUBJECT + "@" + EXPECTED_ISSUER + "\n" + EXPECTED_SUBJECT + "@http://peerIssuer";
        String trusted = EXPECTED_ISSUER + "=http://issuer/keys,http://peerIssuer=http://peerIssuer/keys";

        ClientModel client = mockClient("dummy", description, true);
        String token = mockToken(EXPECTED_SUBJECT, "http://thirdIssuer", EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);

        // when
        authenticatorTrusting(trusted).authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_NOT_FOUND), isNull());
        verify(context, never()).success();
    }

    @Test
    void test_ParseTrustedIssuers() {
        assertThat(KubernetesClientAuthenticator.parseTrustedIssuers(null)).isEmpty();
        assertThat(KubernetesClientAuthenticator.parseTrustedIssuers("  ")).isEmpty();

        assertThat(KubernetesClientAuthenticator.parseTrustedIssuers(
            " https://a/id/1=https://a/id/1/keys , https://b/id/2=https://b/id/2/keys "))
            .containsOnly(
                entry("https://a/id/1", "https://a/id/1/keys"),
                entry("https://b/id/2", "https://b/id/2/keys"));

        assertThat(KubernetesClientAuthenticator.parseTrustedIssuers(
            "https://a/id/1=https://a/id/1/keys\nhttps://b/id/2=https://b/id/2/keys"))
            .hasSize(2);

        assertThatThrownBy(() -> KubernetesClientAuthenticator.parseTrustedIssuers("https://a/id/1"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> KubernetesClientAuthenticator.parseTrustedIssuers("=https://a/id/1/keys"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> KubernetesClientAuthenticator.parseTrustedIssuers("https://a/id/1="))
            .isInstanceOf(IllegalArgumentException.class);
    }

    private static KubernetesClientAuthenticator authenticatorTrusting(String trustedIssuers) {
        Config.Scope config = mock(Config.Scope.class);
        when(config.get(eq(TRUSTED_ISSUERS), anyString())).thenReturn(trustedIssuers);

        KubernetesClientAuthenticator configured = new KubernetesClientAuthenticator();
        configured.init(config);
        return configured;
    }

    @Test
    void test_GetId() {
        assertThat(authenticator.getId()).isEqualTo(PROVIDER_ID);
    }

    @Test
    void test_GetProtocolAuthenticatorMethods() {
        assertThat(authenticator.getProtocolAuthenticatorMethods(LOGIN_PROTOCOL))
            .hasSize(1)
            .contains(PRIVATE_KEY_JWT);

        assertThat(authenticator.getProtocolAuthenticatorMethods("dummyProtocol"))
            .isEmpty();
    }
}
