# keycloak-kubernetes-authenticator

Keycloak client authenticator plugin (SPI) enabling Kubernetes service account JWT tokens as OAuth 2.0 client credentials. Implements RFC 7523 Section 2.2. Fork hosted on GitHub.

## Architecture

Source in `src/main/java/de/chrfritz/keycloak/kubernetes/authenticator/impl/`:

| Class | Purpose |
|-------|---------|
| `KubernetesClientAuthenticator` | Main authenticator — validates JWT signatures, audiences, expiration. Provider ID: `kubernetes-jwt` |
| `ExtendedJwtClientValidator` | Custom client matching via service account + issuer in client description field |
| `TokenValidationException` | Validation error type |

### Client Matching

Kubernetes service accounts are identified by the client's description field in format:
```
system:serviceaccount:<namespace>:<name>@<issuer>
```

### Token Validation

- Validates JWT signature, expiration, audience (issuer URL, token endpoint, PAR endpoint, CIBA endpoint)
- Token reuse check intentionally disabled (Kubernetes pods may retry with same token)

### SPI Registration

Registered via `src/main/resources/META-INF/services/org.keycloak.authentication.ClientAuthenticatorFactory`.

## Key Files

- `build.gradle.kts` — Keycloak version pin (`26.4.0`), Java 17 toolchain
- `build/libs/keycloak-kubernetes-authenticator.jar` — output JAR
- `src/main/docker-initContainer/` — init container Dockerfile for Kubernetes deployment

## Commands

```bash
# Build and test
./gradlew build

# Run tests
./gradlew test

# Run single test class
./gradlew test --tests "de.chrfritz.keycloak.kubernetes.authenticator.impl.SomeTest"

# Code coverage report
./gradlew jacocoTestReport
```

## Conventions

- **Git workflow:** Branch naming `JIRA-TICKET-kebab-case`, commit format `JIRA-TICKET - imperative-lowercase-description`
- **CI:** GitHub Actions (not GitLab CI) — build, release, CodeQL, Dependabot
- **Publishing:** Maven publication to GitHub Packages (requires `GITHUB_ACTOR` + `GITHUB_TOKEN`)
- **Default branch:** `main`
- **Note:** This is a GitHub fork (`martin-ducar-gd/keycloak-kubernetes-authenticator`), not on GitLab
