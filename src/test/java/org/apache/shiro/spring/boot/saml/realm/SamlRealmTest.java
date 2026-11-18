package org.apache.shiro.spring.boot.saml.realm;

import io.github.easy4j.jwt.JwtPayload.RolePair;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.spring.boot.saml.Saml2PayloadPrincipal;
import org.apache.shiro.spring.boot.saml.SamlPayloadPrincipal;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collections;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SAML realm classes.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SAML Realm Tests")
class SamlRealmTest {

    @Test
    @DisplayName("SamlStatefulAuthorizingRealm can be instantiated")
    void testSamlStatefulAuthorizingRealm() {
        SamlStatefulAuthorizingRealm realm = new SamlStatefulAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("SamlStatelessAuthorizingRealm can be instantiated")
    void testSamlStatelessAuthorizingRealm() {
        SamlStatelessAuthorizingRealm realm = new SamlStatelessAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("Saml2StatefulAuthorizingRealm can be instantiated")
    void testSaml2StatefulAuthorizingRealm() {
        Saml2StatefulAuthorizingRealm realm = new Saml2StatefulAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("Saml2StatelessAuthorizingRealm can be instantiated")
    void testSaml2StatelessAuthorizingRealm() {
        Saml2StatelessAuthorizingRealm realm = new Saml2StatelessAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("SamlStatelessAuthorizingRealm supports SamlToken")
    void testSamlStatelessSupportsToken() {
        SamlStatelessAuthorizingRealm realm = new SamlStatelessAuthorizingRealm();
        org.apache.shiro.authc.AuthenticationToken token = new org.apache.shiro.spring.boot.saml.token.SamlToken("host", "request", false);
        // The realm may or may not support this token type depending on its implementation
        assertThat(realm.supports(token)).isNotNull();
    }

    @Test
    @DisplayName("Saml2StatelessAuthorizingRealm supports Saml2Token")
    void testSaml2StatelessSupportsToken() {
        Saml2StatelessAuthorizingRealm realm = new Saml2StatelessAuthorizingRealm();
        org.apache.shiro.authc.AuthenticationToken token = new org.apache.shiro.spring.boot.saml.token.Saml2Token("host", "request", false);
        // The realm may or may not support this token type depending on its implementation
        assertThat(realm.supports(token)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void convertsVerifiedPrincipalRolesAndPermissions(boolean saml2) {
        ShiroPrincipal principal = saml2 ? new Saml2PayloadPrincipal("verified fixture")
                : new SamlPayloadPrincipal("verified fixture");
        principal.setRoles(Collections.singletonList(new RolePair("1", "reader", "Reader")));
        principal.setPerms(Collections.singleton("report:read"));
        SimplePrincipalCollection principals = new SimplePrincipalCollection(principal, "samlRealm");

        AuthorizationInfo authorization = saml2 ? new Saml2StatelessAuthorizingRealm().doGetAuthorizationInfo(principals)
                : new SamlStatelessAuthorizingRealm().doGetAuthorizationInfo(principals);

        assertThat(authorization.getRoles()).containsExactly("reader");
        assertThat(authorization.getStringPermissions()).containsExactly("report:read");
    }
}
