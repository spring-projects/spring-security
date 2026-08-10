package org.springframework.security.docs.servlet.authentication.raammfa;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.authorization.MapRequiredAuthoritiesRepository;
import org.springframework.security.authorization.RequiredAuthoritiesAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class RequiredAuthoritiesAuthorizationManagerConfiguration {
	// tag::httpSecurity[]
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/admin/**").hasRole("ADMIN") // <1>
				.anyRequest().authenticated() // <2>
			)
			.formLogin(Customizer.withDefaults())
			.oneTimeTokenLogin(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}
	// end::httpSecurity[]

	// tag::authorizationManager[]
	@Bean
	RequiredAuthoritiesAuthorizationManager<Object> adminAuthorization() {
		// <1>
		MapRequiredAuthoritiesRepository authorities = new MapRequiredAuthoritiesRepository();
		authorities.saveRequiredAuthorities("admin", List.of(
			FactorGrantedAuthority.PASSWORD_AUTHORITY,
			FactorGrantedAuthority.OTT_AUTHORITY)
		);
		// <2>
		return new RequiredAuthoritiesAuthorizationManager<>(authorities);
	}
	// end::authorizationManager[]

	// tag::authorizationManagerFactory[]
	@Bean
	AuthorizationManagerFactory<Object> authorizationManagerFactory(
			RequiredAuthoritiesAuthorizationManager admins) {
		DefaultAuthorizationManagerFactory<Object> defaults = new DefaultAuthorizationManagerFactory<>();
		// <1>
		defaults.setAdditionalAuthorization(admins);
		// <2>
		return defaults;
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
