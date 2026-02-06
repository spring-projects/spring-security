package org.springframework.security.docs.servlet.oauth2.resourceserver.methodsecurityhasscope;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.oauth2.core.authorization.DefaultOAuth2AuthorizationManagerFactory;
import org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagerFactory;

@Configuration
@EnableMethodSecurity
@EnableMultiFactorAuthentication(authorities = { "FACTOR_BEARER", "FACTOR_X509" })
class MethodSecurityHasScopeMfaConfiguration {
	// tag::declare-factory[]
	@Bean
	OAuth2AuthorizationManagerFactory<?> oauth2(AuthorizationManagerFactory<?> authz) {
		return new DefaultOAuth2AuthorizationManagerFactory<>(authz);
	}
	// end::declare-factory[]
}
