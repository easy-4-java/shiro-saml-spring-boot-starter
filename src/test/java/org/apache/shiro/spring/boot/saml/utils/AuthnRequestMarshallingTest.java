package org.apache.shiro.spring.boot.saml.utils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.w3c.dom.Element;

import static org.assertj.core.api.Assertions.assertThat;

class AuthnRequestMarshallingTest {

    @BeforeAll
    static void initializeOpenSaml() throws Exception {
        InitializationService.initialize();
    }

    @Test
    void preservesIssuerAndAssertionConsumerUrlWhenMarshalled() throws Exception {
        String destination = "https://idp.example.test/sso";
        String consumer = "https://sp.example.test/saml/acs";
        String issuer = "urn:example:service-provider";

        AuthnRequest request = AuthnRequestUtils.createRequest(destination, consumer, issuer);
        Element element = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                .getMarshaller(request).marshall(request);

        assertThat(element.getLocalName()).isEqualTo("AuthnRequest");
        assertThat(element.getAttribute("Destination")).isEqualTo(destination);
        assertThat(element.getAttribute("AssertionConsumerServiceURL")).isEqualTo(consumer);
        assertThat(request.getIssuer().getValue()).isEqualTo(issuer);
        assertThat(element.getOwnerDocument().getDocumentElement()).isSameAs(element);
    }

    @Test
    void forceAuthenticationOverloadReturnsAnAuthnRequest() {
        AuthnRequest request = AuthnRequestUtils.createRequest("https://idp.example.test/sso",
                "https://sp.example.test/callback", "urn:fixture:sp", true);

        assertThat(request.isForceAuthn()).isTrue();
        assertThat(request.getIssuer().getValue()).isEqualTo("urn:fixture:sp");
        assertThat(request.getID()).isNotBlank();
    }

    @Test
    void preservesProvidedAuthenticationContext() {
        RequestedAuthnContext requested = new RequestedAuthnContextBuilder().buildObject();
        requested.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

        AuthnRequest request = AuthnRequestUtils.createRequest("https://idp.example.test/sso",
                "https://sp.example.test/callback", "urn:fixture:sp", null, requested, false);

        assertThat(request.getRequestedAuthnContext()).isSameAs(requested);
        assertThat(request.isForceAuthn()).isFalse();
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void exampleRequestGeneratorWritesPostBindingXml(CapturedOutput output) throws Exception {
        new AuthnRequestUtils().generateRequestURL();

        assertThat(output.getOut()).contains("AuthnRequest", "AssertionConsumerServiceURL",
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "RequestedAuthnContext");
    }
}
