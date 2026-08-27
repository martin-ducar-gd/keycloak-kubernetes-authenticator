package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import jakarta.ws.rs.core.Response;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.keys.PublicKeyStorageUtils;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.protocol.oidc.grants.ciba.CibaGrantType;
import org.keycloak.protocol.oidc.par.endpoints.ParEndpoint;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;
import org.keycloak.utils.StringUtil;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class KubernetesClientAuthenticator extends AbstractClientAuthenticator {

    public static final String PROVIDER_ID = "kubernetes-jwt";
    public static final String CUSTOM_AUDIENCE_ENABLED = "custom.audience.enabled";
    public static final String JWK_URLS_ENABLED = "use.jwks.url";
    public static final String TRUSTED_ISSUERS = "trusted-issuers";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    /** Token issuers this instance accepts, mapped to the JWKS endpoint that signs for them. */
    private Map<String, String> trustedIssuers = Map.of();

    @Override
    public void init(Config.Scope config) {
        trustedIssuers = parseTrustedIssuers(config.get(TRUSTED_ISSUERS, ""));
    }

    /**
     * Parses a comma or newline separated list of {@code <issuer>=<jwksUrl>} pairs.
     *
     * A DR pair shares one Keycloak database, so a client's own jwks.url can only ever name one
     * cluster's endpoint. Configuring the issuers here instead lets each instance verify the
     * service account tokens minted by the cluster it runs in, whichever cluster last rendered
     * the realm.
     */
    static Map<String, String> parseTrustedIssuers(String raw) {
        if (raw == null || raw.isBlank()) {
            return Map.of();
        }
        Map<String, String> parsed = new LinkedHashMap<>();
        for (String entry : raw.split("[,\\r\\n]")) {
            String pair = entry.trim();
            if (pair.isEmpty()) {
                continue;
            }
            int separator = pair.indexOf('=');
            if (separator <= 0 || separator == pair.length() - 1) {
                throw new IllegalArgumentException(
                        "Expected '<issuer>=<jwksUrl>' in " + TRUSTED_ISSUERS + " but got '" + pair + "'");
            }
            parsed.put(pair.substring(0, separator).trim(), pair.substring(separator + 1).trim());
        }
        return Map.copyOf(parsed);
    }

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        var params = context.getHttpRequest().getDecodedFormParameters();
        String assertionType = (String) params.getFirst("client_assertion_type");
        String clientAssertion = (String) params.getFirst("client_assertion");

        if (!"urn:ietf:params:oauth:client-assertion-type:jwt-bearer".equals(assertionType)) {
            Response errorResponse = ClientAuthUtil.errorResponse(
                    Response.Status.BAD_REQUEST.getStatusCode(),
                    "invalid_client",
                    "Client assertion type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            context.challenge(errorResponse);
            return;
        }

        if (StringUtil.isNullOrEmpty(clientAssertion)) {
            Response errorResponse = ClientAuthUtil.errorResponse(
                    Response.Status.BAD_REQUEST.getStatusCode(),
                    "invalid_client",
                    "Client assertion not provided");
            context.challenge(errorResponse);
            return;
        }

        try {
            JWSInput jws = new JWSInput(clientAssertion);
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);

            String subject = token.getSubject();
            if (subject == null) {
                throw new TokenValidationException("Can't identify client. Subject missing on JWT token");
            }

            String issuer = token.getIssuer();
            String trustedJwksUrl = issuer == null ? null : trustedIssuers.get(issuer);
            String explicitClientId = (String) params.getFirst("client_id");

            Optional<ClientModel> clientOpt = context.getRealm()
                    .getClientsStream()
                    .filter(c -> matchesClient(subject, issuer, trustedJwksUrl != null, explicitClientId, c))
                    .findFirst();

            if (clientOpt.isEmpty()) {
                context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
                return;
            }

            ClientModel client = clientOpt.get();
            if (!client.isEnabled()) {
                context.failure(AuthenticationFlowError.CLIENT_DISABLED, null);
                return;
            }

            context.setClient(client);

            if (trustedJwksUrl != null) {
                if (!isTokenSignatureValidForIssuer(context, client, jws, issuer, trustedJwksUrl)) {
                    throw new TokenValidationException("Signature on JWT token failed validation");
                }
            } else {
                var publicKey = PublicKeyStorageManager.getClientPublicKey(
                        context.getSession(), client, jws);
                if (publicKey == null) {
                    Response errorResponse = ClientAuthUtil.errorResponse(
                            Response.Status.BAD_REQUEST.getStatusCode(),
                            "invalid_client",
                            "Unable to load public key");
                    context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, errorResponse);
                    return;
                }

                if (!isTokenSignatureValid(context, clientAssertion, client)) {
                    throw new TokenValidationException("Signature on JWT token failed validation");
                }
            }

            List<String> expectedAudiences = getExpectedAudiences(context, client, token);
            if (!token.hasAnyAudience(expectedAudiences)) {
                throw new TokenValidationException(
                        "Token audience doesn't match domain. Expected audiences are any of "
                                + expectedAudiences
                                + " but audience from token is '"
                                + Arrays.asList(token.getAudience()) + "'");
            }

            if (!token.isActive()) {
                throw new TokenValidationException("Token is not active");
            }

            if (token.getExp() == 0L && token.getIat() + 10 < (long) org.keycloak.common.util.Time.currentTime()) {
                throw new TokenValidationException("Token is not active");
            }

            context.success();

        } catch (TokenValidationException e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);
            Response errorResponse = ClientAuthUtil.errorResponse(
                    Response.Status.BAD_REQUEST.getStatusCode(),
                    "invalid_client",
                    e.getMessage());
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, errorResponse);
        } catch (Exception e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);
            Response errorResponse = ClientAuthUtil.errorResponse(
                    Response.Status.BAD_REQUEST.getStatusCode(),
                    "invalid_client",
                    e.getMessage());
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, errorResponse);
        }
    }

    private static boolean matchesClient(String subject, String issuer, boolean issuerTrusted,
                                          String explicitClientId, ClientModel client) {
        if (StringUtil.isNullOrEmpty(client.getDescription())) {
            return false;
        }
        if (!describesServiceAccount(client.getDescription(), subject, issuer, issuerTrusted)) {
            return false;
        }
        // When client_id is explicitly provided, require it to match as well.
        // This disambiguates when multiple clients share the same service account description.
        if (explicitClientId != null && !explicitClientId.isEmpty()) {
            return explicitClientId.equals(client.getClientId());
        }
        return true;
    }

    /**
     * Whether a description line binds the client to the service account presenting the token.
     *
     * A line reads {@code <subject>@<issuer>}. The issuer has to match unless this instance was
     * configured to trust the token's issuer: the members of a DR pair share one Keycloak database
     * but mint tokens under their own issuer, so the stored line names whichever cluster rendered
     * the realm last, while the subject is the same on both.
     */
    private static boolean describesServiceAccount(String description, String subject, String issuer,
                                                    boolean issuerTrusted) {
        for (String line : description.split("\r\n|\n|\r")) {
            String candidate = line.trim();
            if (candidate.equals(subject + "@" + issuer)) {
                return true;
            }
            if (issuerTrusted && candidate.startsWith(subject + "@")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verifies the token against the JWKS endpoint configured for its issuer, bypassing the
     * client's own key configuration.
     */
    private static boolean isTokenSignatureValidForIssuer(ClientAuthenticationFlowContext context,
                                                          ClientModel client,
                                                          JWSInput jws,
                                                          String issuer,
                                                          String jwksUrl) {
        try {
            KeycloakSession session = context.getSession();
            JWSHeader header = jws.getHeader();
            String algorithm = header.getRawAlgorithm();

            // Keyed per issuer so the members of a DR pair cannot evict each other's keys.
            String cacheKey = PublicKeyStorageUtils
                    .getClientModelCacheKey(context.getRealm().getId(), client.getId()) + "::" + issuer;

            KeyWrapper key = session.getProvider(PublicKeyStorageProvider.class)
                    .getPublicKey(cacheKey, header.getKeyId(), algorithm,
                            new JwksUrlPublicKeyLoader(session, issuer, jwksUrl));
            if (key == null) {
                throw new TokenValidationException(
                        "No key with id '" + header.getKeyId() + "' at the JWKS endpoint of issuer '" + issuer + "'");
            }

            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, algorithm);
            if (signatureProvider == null) {
                throw new TokenValidationException("Unsupported signature algorithm '" + algorithm + "'");
            }

            return signatureProvider.verifier(key)
                    .verify(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8), jws.getSignature());
        } catch (TokenValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new TokenValidationException("Signature on JWT token failed validation", e);
        }
    }

    private static boolean isTokenSignatureValid(ClientAuthenticationFlowContext context,
                                                  String clientAssertion,
                                                  ClientModel client) {
        try {
            JsonWebToken decoded = context.getSession().tokens()
                    .decodeClientJWT(clientAssertion, client, (jose, c) -> {}, JsonWebToken.class);
            return decoded != null;
        } catch (RuntimeException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new RuntimeException("Signature on JWT token failed validation", cause);
        }
    }

    private List<String> getExpectedAudiences(ClientAuthenticationFlowContext context,
                                               ClientModel client,
                                               JsonWebToken token) {
        RealmModel realm = context.getRealm();
        var uriInfo = context.getUriInfo();

        String realmIssuer = Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName());
        String tokenUrl = OIDCLoginProtocolService.tokenUrl(uriInfo.getBaseUriBuilder())
                .build(realm.getName()).toString();
        String parUrl = ParEndpoint.parUrl(uriInfo.getBaseUriBuilder())
                .build(realm.getName()).toString();
        String cibaUrl = CibaGrantType.authorizationUrl(uriInfo.getBaseUriBuilder())
                .build(realm.getName()).toString();

        List<String> audiences = new ArrayList<>();
        audiences.add(realmIssuer);
        audiences.add(tokenUrl);
        audiences.add(parUrl);
        audiences.add(cibaUrl);

        boolean customAudienceEnabled = Boolean.parseBoolean(client.getAttribute(CUSTOM_AUDIENCE_ENABLED));
        boolean useJwksUrl = Boolean.parseBoolean(client.getAttribute(JWK_URLS_ENABLED));
        String issuer = token.getIssuer();

        if (customAudienceEnabled && useJwksUrl && issuer != null) {
            String jwksUrl = client.getAttribute("jwks.url");
            if (jwksUrl != null && !jwksUrl.isEmpty()) {
                // Extract base URL: find first '/' after '//'
                int slashAfterProtocol = jwksUrl.indexOf("//");
                int firstPathSlash = slashAfterProtocol >= 0
                        ? jwksUrl.indexOf('/', slashAfterProtocol + 2)
                        : -1;

                if (firstPathSlash != -1) {
                    String baseUrl = jwksUrl.substring(0, firstPathSlash);
                    if (baseUrl.equals(issuer)) {
                        audiences.add(baseUrl);
                    } else {
                        ServicesLogger.LOGGER.debugf(
                                "Token issuer '%s' does not match base URL from jwks.url '%s'",
                                issuer, baseUrl);
                    }
                } else {
                    if (jwksUrl.equals(issuer)) {
                        audiences.add(jwksUrl);
                    } else {
                        ServicesLogger.LOGGER.debugf(
                                "Token issuer '%s' does not match jwks.url '%s'",
                                issuer, jwksUrl);
                    }
                }
            }
            audiences.add("https://kubernetes.default.svc");
        }

        return audiences;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "Validates client based on signed JWT issued by client and signed with the Client private key";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        ProviderConfigProperty prop = new ProviderConfigProperty();
        prop.setName(CUSTOM_AUDIENCE_ENABLED);
        prop.setLabel("Enable Custom Audiences");
        prop.setType("boolean");
        prop.setDefaultValue("false");
        prop.setHelpText("Enable support for custom JWT audiences from client attributes (jwks.url) trimmed to base URL");
        return List.of(prop);
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        return new HashMap<>();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        if (java.util.Objects.equals(loginProtocol, "openid-connect")) {
            Set<String> set = new HashSet<>();
            set.add("private_key_jwt");
            return set;
        }
        return Collections.emptySet();
    }

    @Override
    public String getDisplayType() {
        return "Kubernetes Service Account";
    }
}
