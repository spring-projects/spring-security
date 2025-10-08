package org.springframework.security.docs.servlet.authentication.obtainingmoreauthorization;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class MissingAuthorityConfiguration {

	// tag::httpSecurity[]
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, ScopeRetrievingAuthenticationEntryPoint oauth2) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/profile/**").hasAuthority("SCOPE_profile:read")
				.anyRequest().authenticated()
			)
			.x509(Customizer.withDefaults())
			.oauth2Login(Customizer.withDefaults())
			.exceptionHandling((exceptions) -> exceptions
				.defaultDeniedHandlerForMissingAuthority(oauth2, "SCOPE_profile:read")
			);
		// @formatter:on
		return http.build();
	}
	// end::httpSecurity[]

	// tag::authorizationManagerFactoryBean[]
	@Bean
	AuthorizationManagerFactory<Object> authz() {
		return DefaultAuthorizationManagerFactory.builder()
				.requireAdditionalAuthorities(FactorGrantedAuthority.X509_AUTHORITY, FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY)
				.build();
	}
	// end::authorizationManagerFactoryBean[]

	// tag::authenticationEntryPoint[]
	@Component
	class ScopeRetrievingAuthenticationEntryPoint implements AuthenticationEntryPoint {
		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
				throws IOException, ServletException {
			response.sendRedirect("https://authz.example.org/authorize?scope=profile:read");
		}
	}
	// end::authenticationEntryPoint[]

	@Bean
	ClientRegistrationRepository clients() {
		return new InMemoryClientRegistrationRepository(TestClientRegistrations.clientRegistration().build());
	}
}
