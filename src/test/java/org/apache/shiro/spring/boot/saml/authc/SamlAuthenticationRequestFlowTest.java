package org.apache.shiro.spring.boot.saml.authc;

import com.alibaba.fastjson.JSONObject;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.spring.boot.saml.exception.ExpiredSamlException;
import org.apache.shiro.spring.boot.saml.exception.IncorrectSamlException;
import org.apache.shiro.spring.boot.saml.exception.InvalidSamlToken;
import org.apache.shiro.spring.boot.saml.token.SamlToken;
import org.apache.shiro.spring.boot.saml.token.Saml2Token;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SamlAuthenticationRequestFlowTest {

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void postsCallbackThroughSubjectAndWritesVerifiedPrincipal(boolean saml2) throws Exception {
        SamlAuthenticatingFilter legacy = new SamlAuthenticatingFilter();
        Saml2AuthenticatingFilter modern = new Saml2AuthenticatingFilter();
        legacy.setLoginUrl("/callback");
        modern.setLoginUrl("/callback");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/callback");
        request.setServletPath("/callback");
        request.addParameter("SAMLRequest", "callback fixture");
        MockHttpServletResponse response = new MockHttpServletResponse();

        ShiroPrincipal principal = new ShiroPrincipal();
        principal.setUserid("fixture-user");
        Subject subject = mock(Subject.class);
        when(subject.getPrincipal()).thenReturn(principal);

        ThreadContext.bind(subject);
        try {
            boolean proceeds = saml2 ? modern.onAccessDenied(request, response) : legacy.onAccessDenied(request, response);
            assertThat(proceeds).isFalse();
        } finally {
            ThreadContext.unbindSubject();
        }
        verify(subject).login(argThat(token -> (saml2 ? token instanceof Saml2Token : token instanceof SamlToken)
                && "callback fixture".equals(token.getCredentials())));
        JSONObject body = JSONObject.parseObject(response.getContentAsString());
        assertThat(body.getString("status")).isEqualTo("success");
        assertThat(body.getJSONObject("principal").getString("userid")).isEqualTo("fixture-user");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectsGetAtLoginEndpointAndMissingCredentialsAtProtectedEndpoint(boolean saml2) throws Exception {
        SamlAuthenticatingFilter legacy = new SamlAuthenticatingFilter();
        Saml2AuthenticatingFilter modern = new Saml2AuthenticatingFilter();
        legacy.setLoginUrl("/saml/login");
        modern.setLoginUrl("/saml/login");
        MockHttpServletRequest login = new MockHttpServletRequest("GET", "/saml/login");
        login.setServletPath("/saml/login");
        MockHttpServletResponse loginResponse = new MockHttpServletResponse();

        boolean proceeds = saml2 ? modern.onAccessDenied(login, loginResponse) : legacy.onAccessDenied(login, loginResponse);
        assertThat(proceeds).isFalse();
        assertThat(loginResponse.getStatus()).isEqualTo(400);

        MockHttpServletRequest missing = new MockHttpServletRequest("GET", "/private");
        MockHttpServletResponse missingResponse = new MockHttpServletResponse();
        proceeds = saml2 ? modern.onAccessDenied(missing, missingResponse) : legacy.onAccessDenied(missing, missingResponse);
        assertThat(proceeds).isFalse();
        assertThat(JSONObject.parseObject(missingResponse.getContentAsString()).getString("status")).isEqualTo("fail");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void readsConfiguredCredentialLocationsAndReportsRejectedCredentials(boolean saml2) throws Exception {
        SamlAuthenticatingFilter legacy = new SamlAuthenticatingFilter();
        Saml2AuthenticatingFilter modern = new Saml2AuthenticatingFilter();
        legacy.setAuthorizationHeaderName("X-Saml");
        modern.setAuthorizationHeaderName("X-Saml");
        legacy.setAuthorizationParamName("payload");
        modern.setAuthorizationParamName("payload");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/callback");
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addParameter("payload", "parameter fixture");
        AuthenticationToken fromParameter = saml2 ? modern.createToken(request, response) : legacy.createToken(request, response);
        assertThat(fromParameter).isExactlyInstanceOf(saml2 ? Saml2Token.class : SamlToken.class);
        assertThat(fromParameter.getCredentials()).isEqualTo("parameter fixture");

        request.addHeader("X-Saml", "header fixture");
        AuthenticationToken fromHeader = saml2 ? modern.createToken(request, response) : legacy.createToken(request, response);
        assertThat(fromHeader.getCredentials()).isEqualTo("header fixture");

        Exception[] errors = {new IncorrectSamlException("incorrect"), new InvalidSamlToken("invalid"), new ExpiredSamlException("expired")};
        String[] categories = {"incorrect", "invalid", "expiry"};
        for (int index = 0; index < errors.length; index++) {
            MockHttpServletResponse rejection = new MockHttpServletResponse();
            boolean proceeds = saml2 ? modern.onAccessFailure(fromHeader, errors[index], request, rejection)
                    : legacy.onAccessFailure(fromHeader, errors[index], request, rejection);
            assertThat(proceeds).isFalse();
            JSONObject body = JSONObject.parseObject(rejection.getContentAsString());
            assertThat(body.getString("status")).isEqualTo("fail");
            assertThat(body.getString("token")).isEqualTo(categories[index]);
        }
    }
}
