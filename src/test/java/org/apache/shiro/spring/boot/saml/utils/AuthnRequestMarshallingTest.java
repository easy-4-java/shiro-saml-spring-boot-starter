package org.apache.shiro.spring.boot.saml.utils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
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
}
