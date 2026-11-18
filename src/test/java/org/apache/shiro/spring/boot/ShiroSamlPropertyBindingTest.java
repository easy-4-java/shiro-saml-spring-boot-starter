package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.saml.AuthnContextComparisonType;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ShiroSamlPropertyBindingTest {

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void bindsProviderIdentityEndpointsAndRequestParameterNames(boolean saml2) {
        String prefix = saml2 ? ShiroSaml2Properties.PREFIX : ShiroSamlProperties.PREFIX;
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(prefix + ".enabled", "true");
        properties.put(prefix + ".destination-url", "https://idp.example.test/sso");
        properties.put(prefix + ".assertion-consumer-service-url", "https://sp.example.test/callback");
        properties.put(prefix + ".sp-entity-id", "urn:fixture:sp");
        properties.put(prefix + ".unauthorized-url", "/denied");
        properties.put(prefix + ".force-authn", "true");
        properties.put(prefix + ".saml-request-parameter-name", "SAMLResponse");
        properties.put(prefix + ".relay-state-parameter-name", "state");
        properties.put(prefix + ".comparison-type", "exact");
        Binder binder = new Binder(new MapConfigurationPropertySource(properties));
        Object bound = saml2 ? binder.bind(prefix, Bindable.of(ShiroSaml2Properties.class)).get()
                : binder.bind(prefix, Bindable.of(ShiroSamlProperties.class)).get();

        assertThat(bound).extracting("enabled", "destinationURL", "assertionConsumerServiceURL",
                        "spEntityId", "unauthorizedUrl", "forceAuthn", "samlRequestParameterName",
                        "relayStateParameterName", "comparisonType")
                .containsExactly(true, "https://idp.example.test/sso", "https://sp.example.test/callback",
                        "urn:fixture:sp", "/denied", true, "SAMLResponse", "state", AuthnContextComparisonType.exact);
    }
}
