package org.springframework.security.docs.servlet.authentication.mfawhencustomconditions;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.config.Customizer;

@Configuration(proxyBeanMethods = false)
class CustomizerAuthorizationManagerFactoryConfiguration {

	// tag::customizer[]
	@Bean
	Customizer<AuthorizationManagerFactories.AdditionalRequiredFactorsBuilder<Object>> additionalRequiredFactorsCustomizer() {
		return (builder) -> builder.when((auth) -> "admin".equals(auth.getName()));
	}
	// end::customizer[]

}
