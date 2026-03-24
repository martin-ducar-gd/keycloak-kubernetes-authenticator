---
name: build-jar
description: Build keycloak-kubernetes-authenticator JAR and run tests
---

## Build Project

1. Build and run tests:
   ```bash
   ./gradlew build
   ```

2. Verify output JAR exists:
   ```bash
   ls -la build/libs/keycloak-kubernetes-authenticator*.jar
   ```

3. Optionally generate coverage report:
   ```bash
   ./gradlew jacocoTestReport
   ```

4. Report test results and JAR filename to the user.
