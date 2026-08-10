package org.springframework.security.docs.servlet.authentication.programmaticmfa;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class AdminMfaAuthorizationManagerConfiguration {
	// tag::httpSecurity[]
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				// <1>
				.requestMatchers("/admin/**").hasRole("ADMIN")
				// <2>
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults())
			.oneTimeTokenLogin(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}
	// end::httpSecurity[]

	// tag::authorizationManagerFactory[]
	@Bean
	AuthorizationManagerFactory<Object> authorizationManagerFactory() {
		// <3>
		return AuthorizationManagerFactories.multiFactor()
			// <1>
			.requireFactors(FactorGrantedAuthority.OTT_AUTHORITY, FactorGrantedAuthority.PASSWORD_AUTHORITY)
			// <2>
			.when((auth) -> "admin".equals(auth.getName()))
			.build();
	}
	// end::authorizationManagerFactory[]

	@Bean
	public UserDetailsService users() {
		return new InMemoryUserDetailsManager(PasswordEncodedUser.user(), PasswordEncodedUser.admin());
	}

	@Bean
	OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler() {
		return new RedirectOneTimeTokenGenerationSuccessHandler("/ott/sent");
	}
}
