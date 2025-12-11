package org.springframework.security.docs.servlet.authentication.programmaticmfa;

import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AllAuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
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
import org.springframework.stereotype.Component;

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

	// tag::authorizationManager[]
	@Component
	class AdminMfaAuthorizationManager implements AuthorizationManager<Object> {
		@Override
		public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication, Object context) {
			if ("admin".equals(authentication.get().getName())) {
				AuthorizationManager<Object> admins =
					AllAuthoritiesAuthorizationManager.hasAllAuthorities(
						FactorGrantedAuthority.OTT_AUTHORITY,
						FactorGrantedAuthority.PASSWORD_AUTHORITY
					);
				// <1>
				return admins.authorize(authentication, context);
			} else {
				// <2>
				return new AuthorizationDecision(true);
			}
		}
	}
	// end::authorizationManager[]

	// tag::authorizationManagerFactory[]
	@Bean
	AuthorizationManagerFactory<Object> authorizationManagerFactory(
			AdminMfaAuthorizationManager admins) {
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
