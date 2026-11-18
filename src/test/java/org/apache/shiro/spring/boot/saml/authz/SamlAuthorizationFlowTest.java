package org.apache.shiro.spring.boot.saml.authz;

import com.alibaba.fastjson.JSONObject;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.spring.boot.saml.exception.ExpiredSamlException;
import org.apache.shiro.spring.boot.saml.exception.IncorrectSamlException;
import org.apache.shiro.spring.boot.saml.exception.InvalidSamlToken;
import org.apache.shiro.spring.boot.saml.token.Saml2Token;
import org.apache.shiro.spring.boot.saml.token.SamlToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class SamlAuthorizationFlowTest {

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void authorizedRequestDelegatesToSubjectAndRejectedCredentialsStopTheChain(boolean saml2) throws Exception {
        SamlAuthorizationFilter legacy = new SamlAuthorizationFilter();
        Saml2AuthorizationFilter modern = new Saml2AuthorizationFilter();
        legacy.setSessionStateless(false);
        modern.setSessionStateless(false);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/protected");
        request.addParameter("SAMLRequest", "parameter fixture");
        request.addHeader("Authorization", "header fixture");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Subject subject = mock(Subject.class);

        ThreadContext.bind(subject);
        try {
            boolean allowed = saml2 ? modern.onPreHandle(request, response, null) : legacy.onPreHandle(request, response, null);
            assertThat(allowed).isTrue();
            verify(subject).login(argThat(token -> (saml2 ? token instanceof Saml2Token : token instanceof SamlToken)
                    && "header fixture".equals(token.getCredentials())));

            doThrow(new AuthenticationException("rejected by test verifier")).when(subject).login(any(AuthenticationToken.class));
            allowed = saml2 ? modern.onPreHandle(request, response, null) : legacy.onPreHandle(request, response, null);
            assertThat(allowed).isFalse();
        } finally {
            ThreadContext.unbindSubject();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void missingCredentialAndMappedFailuresDoNotEnterTheChain(boolean saml2) throws Exception {
        SamlAuthorizationFilter legacy = new SamlAuthorizationFilter();
        Saml2AuthorizationFilter modern = new Saml2AuthorizationFilter();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean allowed = saml2 ? modern.onPreHandle(request, response, null) : legacy.onPreHandle(request, response, null);
        assertThat(allowed).isFalse();
        assertThat(JSONObject.parseObject(response.getContentAsString()).getString("status")).isEqualTo("fail");

        Exception[] failures = {new IncorrectSamlException("incorrect"), new InvalidSamlToken("invalid"),
                new ExpiredSamlException("expired"), new IllegalStateException("verification failed")};
        String[] categories = {"incorrect", "invalid", "expiry", null};
        for (int index = 0; index < failures.length; index++) {
            MockHttpServletResponse rejected = new MockHttpServletResponse();
            allowed = saml2 ? modern.onAccessFailure(null, failures[index], request, rejected)
                    : legacy.onAccessFailure(null, failures[index], request, rejected);
            assertThat(allowed).isFalse();
            JSONObject result = JSONObject.parseObject(rejected.getContentAsString());
            assertThat(result.getString("status")).isEqualTo("fail");
            assertThat(result.getString("token")).isEqualTo(categories[index]);
        }
    }
}
