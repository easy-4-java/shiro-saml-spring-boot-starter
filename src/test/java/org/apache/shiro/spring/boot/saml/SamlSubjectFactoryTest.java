package org.apache.shiro.spring.boot.saml;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.spring.boot.saml.token.Saml2Token;
import org.apache.shiro.spring.boot.saml.token.SamlToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link SamlSubjectFactory }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SamlSubjectFactory Tests")
class SamlSubjectFactoryTest {

    @Test
    @DisplayName("Constructor with sessionCreationEnabled")
    void testConstructor() {
        SamlSubjectFactory factory = new SamlSubjectFactory(true);
        assertThat(factory).isNotNull();
    }

    @Test
    @DisplayName("Constructor with false creates non-null instance")
    void testConstructorWithFalse() {
        SamlSubjectFactory factory = new SamlSubjectFactory(false);
        assertThat(factory).isNotNull();
    }

    @ParameterizedTest
    @CsvSource({"false, false", "false, true", "true, false", "true, true"})
    void rememberedIdentityDoesNotStandInForFreshAuthentication(boolean saml2, boolean rememberMe) {
        DefaultSubjectContext context = new DefaultSubjectContext();
        context.setSecurityManager(new DefaultSecurityManager());
        context.setPrincipals(new SimplePrincipalCollection("verified fixture", "samlRealm"));
        context.setAuthenticated(true);
        context.setAuthenticationToken(saml2 ? new Saml2Token("loopback", "fixture", rememberMe)
                : new SamlToken("loopback", "fixture", rememberMe));

        Subject subject = new SamlSubjectFactory(false).createSubject(context);

        assertThat(subject.isAuthenticated()).isEqualTo(!rememberMe);
    }
}
