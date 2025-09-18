package org.springframework.security.docs.servlet.authentication.obtainingmoreauthorization;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import static org.springframework.security.authorization.AllAuthoritiesAuthorizationManager.hasAllAuthorities;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;

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
	AuthorizationManagerFactory<RequestAuthorizationContext> authz() {
		return new FactorAuthorizationManagerFactory(hasAllAuthorities("FACTOR_X509", "FACTOR_AUTHORIZATION_CODE"));
	}
	// end::authorizationManagerFactoryBean[]

	// tag::authorizationManagerFactory[]
	class FactorAuthorizationManagerFactory implements AuthorizationManagerFactory<RequestAuthorizationContext> {
		private final AuthorizationManager<RequestAuthorizationContext> hasAuthorities;
		private final DefaultAuthorizationManagerFactory<RequestAuthorizationContext> delegate =
				new DefaultAuthorizationManagerFactory<>();

		FactorAuthorizationManagerFactory(AuthorizationManager<RequestAuthorizationContext> hasAuthorities) {
			this.hasAuthorities = hasAuthorities;
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> permitAll() {
			return this.delegate.permitAll();
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> denyAll() {
			return this.delegate.denyAll();
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> hasRole(String role) {
			return hasAnyRole(role);
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> hasAnyRole(String... roles) {
			return allOf(new AuthorizationDecision(false), this.hasAuthorities, this.delegate.hasAnyRole(roles));
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> hasAllRoles(String... roles) {
			return allOf(new AuthorizationDecision(false), this.hasAuthorities, this.delegate.hasAllRoles(roles));
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> hasAuthority(String authority) {
			return hasAnyAuthority(authority);
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> hasAnyAuthority(String... authorities) {
			return allOf(new AuthorizationDecision(false), this.hasAuthorities, this.delegate.hasAnyAuthority(authorities));
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> hasAllAuthorities(String... authorities) {
			return allOf(new AuthorizationDecision(false), this.hasAuthorities, this.delegate.hasAllAuthorities(authorities));
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> authenticated() {
			return allOf(new AuthorizationDecision(false), this.hasAuthorities, this.delegate.authenticated());
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> fullyAuthenticated() {
			return allOf(new AuthorizationDecision(false), this.hasAuthorities, this.delegate.fullyAuthenticated());
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> rememberMe() {
			return allOf(new AuthorizationDecision(false), this.hasAuthorities, this.delegate.rememberMe());
		}

		@Override
		public AuthorizationManager<RequestAuthorizationContext> anonymous() {
			return this.delegate.anonymous();
		}
	}
	// end::authorizationManagerFactory[]

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
