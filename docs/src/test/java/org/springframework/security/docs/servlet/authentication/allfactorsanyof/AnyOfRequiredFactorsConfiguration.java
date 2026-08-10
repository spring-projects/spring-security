package org.springframework.security.docs.servlet.authentication.allfactorsanyof;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class AnyOfRequiredFactorsConfiguration {

	// tag::httpSecurity[]
	@Bean
	SecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
		// @formatter:off
		// <1>
		AllRequiredFactorsAuthorizationManager<Object> webauthn = AllRequiredFactorsAuthorizationManager
				.<Object>builder()
				.requireFactor((factor) -> factor.webauthnAuthority())
				.build();
		// <2>
		AllRequiredFactorsAuthorizationManager<Object> passwordAndOtt = AllRequiredFactorsAuthorizationManager
				.<Object>builder()
				.requireFactor((factor) -> factor.passwordAuthority())
				.requireFactor((factor) -> factor.ottAuthority())
				.build();
		// <3>
		DefaultAuthorizationManagerFactory<Object> mfa = new DefaultAuthorizationManagerFactory<>();
		mfa.setAdditionalAuthorization(AllRequiredFactorsAuthorizationManager.anyOf(webauthn, passwordAndOtt));
		http
			.authorizeHttpRequests((authorize) -> authorize
				// <4>
				.requestMatchers("/protected/**").access(mfa.authenticated())
				// <5>
				.anyRequest().authenticated()
			)
			// <6>
			.formLogin(Customizer.withDefaults())
			.oneTimeTokenLogin(Customizer.withDefaults())
			.webAuthn((webAuthn) -> webAuthn
				.rpName("Spring Security")
				.rpId("example.com")
				.allowedOrigins("https://example.com")
			);
		// @formatter:on
		return http.build();
	}

	// end::httpSecurity[]

	@Bean
	UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.authorities("app")
						.build()
		);
	}

	@Bean
	OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler() {
		return new RedirectOneTimeTokenGenerationSuccessHandler("/ott/sent");
	}

}
