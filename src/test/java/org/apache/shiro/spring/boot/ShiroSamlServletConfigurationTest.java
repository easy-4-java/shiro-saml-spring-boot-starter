package org.apache.shiro.spring.boot;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.support.DefaultEventBus;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;

class ShiroSamlServletConfigurationTest {

    @ParameterizedTest
    @ValueSource(strings = {"saml", "saml2"})
    void startsWithOneOuterServletFilterAndSelectedRealm(String mode) {
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
                        "shiro.filter-chain-definition-map.[/callback]=authc",
                        "shiro.filter-chain-definition-map.[/**]=authc")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeansOfType(Realm.class)).containsKey("samlRealm");
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
