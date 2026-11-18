package org.apache.shiro.spring.boot;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.support.DefaultEventBus;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.apache.shiro.spring.boot.saml.realm.SamlStatelessAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.realm.Saml2StatelessAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.realm.SamlStatefulAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.realm.Saml2StatefulAuthorizingRealm;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;

class ShiroSamlServletConfigurationTest {

    @ParameterizedTest
    @CsvSource({"saml, false, minimum", "saml, true, minimum", "saml2, false, exact",
            "saml2, true, maximum", "saml2, true, better", "saml2, true, minimum"})
    void startsWithOneOuterServletFilterAndSelectedRealm(String mode, boolean stateless, String comparison) {
        boolean saml2 = "saml2".equals(mode);
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        ShiroBizAutoConfiguration.class, ShiroBizWebAutoConfiguration.class,
                        ShiroBizWebFilterConfiguration.class,
                        saml2 ? ShiroSaml2WebAutoConfiguration.class : ShiroSamlWebAutoConfiguration.class,
                        saml2 ? ShiroSaml2WebFilterConfiguration.class : ShiroSamlWebFilterConfiguration.class))
                .withBean(EventBus.class, DefaultEventBus::new)
                .withBean(CacheManager.class, MemoryConstrainedCacheManager::new)
                .withPropertyValues("shiro.enabled=true", "shiro." + mode + ".enabled=true",
                        "shiro.static-security-manager-enabled=false",
                        "shiro.session-stateless=" + stateless,
                        "shiro." + mode + ".comparison-type=" + comparison,
                        "shiro.filter-chain-definition-map.[/callback]=authc",
                        "shiro.filter-chain-definition-map.[/**]=authc")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeansOfType(Realm.class)).containsKey("samlRealm");
                    Class<? extends Realm> expectedRealm = saml2
                            ? (stateless ? Saml2StatelessAuthorizingRealm.class : Saml2StatefulAuthorizingRealm.class)
                            : (stateless ? SamlStatelessAuthorizingRealm.class : SamlStatefulAuthorizingRealm.class);
                    assertThat(context.getBean("samlRealm")).isInstanceOf(expectedRealm);
                    if (saml2) {
                        assertThat(context.getBean(RequestedAuthnContext.class).getComparison().toString())
                                .isEqualTo(comparison);
                    }
                    FilterRegistrationBean<?> outer = context.getBean(
                            "filterShiroFilterRegistrationBean", FilterRegistrationBean.class);
                    assertThat(outer.isEnabled()).isTrue();
                    ShiroFilterFactoryBean factory = context.getBean(
                            "&shiroFilterFactoryBean", ShiroFilterFactoryBean.class);
                    assertThat(factory.getFilterChainDefinitionMap()).containsEntry("/**", "authc");
                    assertThat(factory.getFilters()).containsKeys("authc", "logout");
                    assertThat(context.getBean("authc", FilterRegistrationBean.class).isEnabled()).isFalse();
                });
    }
}
