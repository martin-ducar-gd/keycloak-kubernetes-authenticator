package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import org.keycloak.crypto.PublicKeysWrapper;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JWKSUtils;

import org.apache.http.HttpHeaders;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Loads signing keys from a JWKS endpoint that is not tied to a client's own key configuration.
 *
 * The keys are cached by {@link org.keycloak.keys.PublicKeyStorageProvider}, which reloads them
 * when a token arrives with an unknown key id, so a cluster rotating its service account signing
 * keys needs no intervention here.
 */
public class JwksUrlPublicKeyLoader implements PublicKeyLoader {

    static final String SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private static final Logger LOGGER = Logger.getLogger(JwksUrlPublicKeyLoader.class);

    private final KeycloakSession session;
    private final String issuer;
    private final String jwksUrl;

    public JwksUrlPublicKeyLoader(KeycloakSession session, String issuer, String jwksUrl) {
        this.session = session;
        this.issuer = issuer;
        this.jwksUrl = jwksUrl;
    }

    @Override
    public PublicKeysWrapper loadKeys() throws Exception {
        // A Kubernetes API server serves the key set only for this media type; asking for
        // application/json gets a response that deserialises into an empty key set.
        SimpleHttpRequest request = SimpleHttp.create(session)
                .doGet(jwksUrl)
                .header(HttpHeaders.ACCEPT, "application/jwk-set+json");

        String token = localServiceAccountToken();
        if (token != null) {
            request.auth(token);
        }

        JSONWebKeySet jwks = request.asJson(JSONWebKeySet.class);
        if (jwks == null || jwks.getKeys() == null) {
            throw new IOException("No key set returned by the JWKS endpoint " + jwksUrl);
        }
        return JWKSUtils.getKeyWrappersForUse(jwks, JWK.Use.SIG);
    }

    /**
     * The local pod's service account token, but only when it was minted by the issuer being
     * loaded.
     *
     * An in-cluster discovery endpoint requires authentication, unlike a cloud provider's public
     * one. Comparing the issuers first keeps the token from being sent to any other cluster's
     * endpoint.
     */
    private String localServiceAccountToken() {
        Path path = Path.of(SERVICE_ACCOUNT_TOKEN_PATH);
        if (!Files.isReadable(path)) {
            return null;
        }
        try {
            String token = Files.readString(path, StandardCharsets.UTF_8).trim();
            JsonWebToken jwt = new JWSInput(token).readJsonContent(JsonWebToken.class);
            if (issuer.equals(jwt.getIssuer())) {
                return token;
            }
            LOGGER.debugf("Not sending the local service account token to '%s': it was issued by '%s'",
                    issuer, jwt.getIssuer());
            return null;
        } catch (IOException | JWSInputException | RuntimeException e) {
            LOGGER.warn("Failed to read the local service account token", e);
            return null;
        }
    }
}
