package org.apache.shiro.spring.boot;

import com.alibaba.fastjson.JSONObject;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.support.DefaultEventBus;
import org.apache.shiro.spring.boot.saml.Saml2PrincipalRepository;
import org.apache.shiro.spring.boot.saml.authc.Saml2AuthenticatingFilter;
import org.apache.shiro.spring.boot.saml.token.Saml2Token;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import org.joda.time.DateTime;

import static org.assertj.core.api.Assertions.assertThat;

class ShiroSaml2EmbeddedServletTest {

    private static final String IDP = "https://idp.example.test/metadata";
    private static final String SP = "urn:easy4j:test:sp";
    private static final String CALLBACK = "/callback";

    @Test
    void embeddedTomcatAcceptsTrustedAssertionAndRejectsUnsignedUntrustedAndExpiredAssertions() throws Exception {
        InitializationService.initialize();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idp = generator.generateKeyPair();
        KeyPair unrelatedKey = generator.generateKeyPair();
        try (ServletWebServerApplicationContext context = (ServletWebServerApplicationContext)
                new SpringApplicationBuilder(FixtureApplication.class)
                        .web(WebApplicationType.SERVLET)
                        .run("--server.port=0", "--server.address=127.0.0.1",
                                "--shiro.enabled=true", "--shiro.saml2.enabled=true",
                                "--shiro.static-security-manager-enabled=false", "--shiro.session-stateless=false",
                                "--shiro.login-url=" + CALLBACK,
                                "--shiro.filter-chain-definition-map.[/callback]=authc")) {
            String recipient = "http://127.0.0.1:" + context.getWebServer().getPort() + CALLBACK;
            context.getBean(FixturePrincipalRepository.class).configure(idp.getPublic(), recipient);
            FilterRegistrationBean<?> authc = context.getBean("authc", FilterRegistrationBean.class);
            ((Saml2AuthenticatingFilter) authc.getFilter()).setAuthorizationParamName("SAMLResponse");

            HttpResult accepted = post(recipient, response(recipient, SP, DateTime.now().plusMinutes(2), idp));
            assertThat(accepted.status).isEqualTo(200);
            JSONObject body = JSONObject.parseObject(accepted.body);
            assertThat(body.getString("status")).isEqualTo("success");
            assertThat(body.getJSONObject("principal").getString("userid")).isEqualTo("fixture-user");

            assertThat(post(recipient, response(recipient, SP, DateTime.now().plusMinutes(2), null)).status).isEqualTo(401);
            assertThat(post(recipient, response(recipient, SP, DateTime.now().plusMinutes(2), unrelatedKey)).status).isEqualTo(401);
            assertThat(post(recipient, response(recipient, SP, DateTime.now().minusMinutes(1), idp)).status).isEqualTo(401);
            assertThat(post(recipient, response(recipient, "urn:other:sp", DateTime.now().plusMinutes(2), idp)).status).isEqualTo(401);
        }
    }

    private static String response(String recipient, String audienceValue, DateTime expires, KeyPair signer) throws Exception {
        Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID("_" + UUID.randomUUID());
        assertion.setIssueInstant(DateTime.now());
        Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(IDP);
        assertion.setIssuer(issuer);
        Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
        NameID name = build(NameID.DEFAULT_ELEMENT_NAME);
        name.setValue("fixture-user");
        subject.setNameID(name);
        SubjectConfirmation confirmation = build(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        confirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData confirmationData = build(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        confirmationData.setRecipient(recipient);
        confirmationData.setNotOnOrAfter(expires);
        confirmation.setSubjectConfirmationData(confirmationData);
        subject.getSubjectConfirmations().add(confirmation);
        assertion.setSubject(subject);

        Conditions conditions = build(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(DateTime.now().minusMinutes(2));
        conditions.setNotOnOrAfter(expires);
        AudienceRestriction restriction = build(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        Audience audience = build(Audience.DEFAULT_ELEMENT_NAME);
        audience.setAudienceURI(audienceValue);
        restriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(restriction);
        assertion.setConditions(conditions);
        AuthnStatement statement = build(AuthnStatement.DEFAULT_ELEMENT_NAME);
        statement.setAuthnInstant(DateTime.now());
        AuthnContext authenticationContext = build(AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef classRef = build(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        classRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authenticationContext.setAuthnContextClassRef(classRef);
        statement.setAuthnContext(authenticationContext);
        assertion.getAuthnStatements().add(statement);

        Response response = build(Response.DEFAULT_ELEMENT_NAME);
        response.setID("_" + UUID.randomUUID());
        response.setIssueInstant(DateTime.now());
        response.setDestination(recipient);
        Issuer responseIssuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        responseIssuer.setValue(IDP);
        response.setIssuer(responseIssuer);
        Status status = build(Status.DEFAULT_ELEMENT_NAME);
        StatusCode code = build(StatusCode.DEFAULT_ELEMENT_NAME);
        code.setValue(StatusCode.SUCCESS);
        status.setStatusCode(code);
        response.setStatus(status);
        response.getAssertions().add(assertion);
        if (Objects.nonNull(signer)) {
            Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(new BasicCredential(signer.getPublic(), signer.getPrivate()));
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            assertion.setSignature(signature);
        }
        Element root = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
        if (Objects.nonNull(signer)) {
            Signer.signObject(assertion.getSignature());
        }
        return Base64.getEncoder().encodeToString(SerializeSupport.nodeToString(root).getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private static <T extends XMLObject> T build(QName name) {
        return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilderOrThrow(name).buildObject(name);
    }

    private static HttpResult post(String recipient, String response) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(recipient).openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");
        byte[] form = ("SAMLResponse=" + URLEncoder.encode(response, "UTF-8")).getBytes(StandardCharsets.UTF_8);
        connection.setFixedLengthStreamingMode(form.length);
        try {
            try (OutputStream output = connection.getOutputStream()) {
                output.write(form);
            }
            int status = connection.getResponseCode();
            InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            if (Objects.isNull(stream)) {
                return new HttpResult(status, "");
            }
            try (InputStream input = stream) {
                return new HttpResult(status, org.springframework.util.StreamUtils.copyToString(input, StandardCharsets.UTF_8));
            }
        } finally {
            connection.disconnect();
        }
    }

    private static class HttpResult {
        private final int status;
        private final String body;

        HttpResult(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    @Configuration
    @ImportAutoConfiguration({ShiroBizAutoConfiguration.class, ShiroBizWebAutoConfiguration.class,
            ShiroBizWebFilterConfiguration.class, ShiroSaml2WebAutoConfiguration.class,
            ShiroSaml2WebFilterConfiguration.class})
    static class FixtureApplication {
        @Bean
        ServletWebServerFactory servletWebServerFactory() throws UnknownHostException {
            TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(0);
            factory.setAddress(InetAddress.getByName("127.0.0.1"));
            return factory;
        }

        @Bean
        FixturePrincipalRepository fixturePrincipalRepository() {
            return new FixturePrincipalRepository();
        }

        @Bean
        EventBus eventBus() {
            return new DefaultEventBus();
        }

        @Bean
        CacheManager cacheManager() {
            return new MemoryConstrainedCacheManager();
        }

        @Bean
        ServletRegistrationBean<HttpServlet> rejectedCallback() {
            return new ServletRegistrationBean<>(new HttpServlet() {
                @Override
                protected void doPost(HttpServletRequest request, HttpServletResponse response) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                }
            }, CALLBACK);
        }
    }

    /**
     * Test SP trust fixture. This only authenticates responses generated for this test and
     * does not supply production replay protection or AuthnRequest correlation.
     */
    static class FixturePrincipalRepository extends Saml2PrincipalRepository {
        private PublicKey key;
        private String recipient;

        void configure(PublicKey key, String recipient) {
            this.key = key;
            this.recipient = recipient;
        }

        @Override
        public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
            try {
                Saml2Token saml = (Saml2Token) token;
                Element element = XMLObjectProviderRegistrySupport.getParserPool().parse(new ByteArrayInputStream(
                        Base64.getDecoder().decode(saml.getSAMLRequest()))).getDocumentElement();
                Response message = (Response) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                        .getUnmarshaller(element).unmarshall(element);
                if (!recipient.equals(message.getDestination()) || message.getAssertions().size() != 1) {
                    throw new AuthenticationException("Unexpected test response");
                }
                Assertion assertion = message.getAssertions().get(0);
                if (Objects.isNull(assertion.getSignature())
                        || !SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256.equals(assertion.getSignature().getSignatureAlgorithm())) {
                    throw new AuthenticationException("Expected signed test assertion");
                }
                new SAMLSignatureProfileValidator().validate(assertion.getSignature());
                SignatureValidator.validate(assertion.getSignature(), new BasicCredential(key));
                Conditions conditions = assertion.getConditions();
                if (!IDP.equals(assertion.getIssuer().getValue())
                        || conditions.getNotBefore().isAfterNow() || !conditions.getNotOnOrAfter().isAfterNow()
                        || conditions.getAudienceRestrictions().size() != 1
                        || conditions.getAudienceRestrictions().get(0).getAudiences().stream()
                                .noneMatch(audience -> SP.equals(audience.getAudienceURI()))
                        || assertion.getSubject().getSubjectConfirmations().stream().noneMatch(confirmation ->
                                SubjectConfirmation.METHOD_BEARER.equals(confirmation.getMethod())
                                && recipient.equals(confirmation.getSubjectConfirmationData().getRecipient())
                                && confirmation.getSubjectConfirmationData().getNotOnOrAfter().isAfterNow())) {
                    throw new AuthenticationException("Test assertion claims do not match");
                }
                ShiroPrincipal principal = new ShiroPrincipal();
                principal.setUserid(assertion.getSubject().getNameID().getValue());
                return new SimpleAuthenticationInfo(principal, saml.getCredentials(), "fixture");
            } catch (Exception e) {
                throw new AuthenticationException("Test assertion rejected", e);
            }
        }
    }
}
