package org.springframework.security.docs.servlet.authentication.customauthorizationmanagerfactory;

import java.util.Collection;
import java.util.function.Supplier;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthorities;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class CustomAuthorizationManagerFactory {
	// tag::httpSecurity[]
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/admin/**").hasRole("ADMIN")
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
	class OptInToMfaAuthorizationManager implements AuthorizationManager<Object> {
		@Override
		public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication, Object context) {
			MyPrincipal principal = (MyPrincipal) authentication.get().getPrincipal();
			if (principal.optedIn()) {
				SecurityExpressionOperations sec = new SecurityExpressionRoot<>(authentication, context) {};
				return new AuthorityAuthorizationDecision(sec.hasAuthority(GrantedAuthorities.FACTOR_OTT_AUTHORITY),
						AuthorityUtils.createAuthorityList(GrantedAuthorities.FACTOR_OTT_AUTHORITY));
			}
			return new AuthorizationDecision(true);
		}
	}
	// end::authorizationManager[]

	// tag::authorizationManagerFactory[]
	@Bean
	AuthorizationManagerFactory<Object> authorizationManagerFactory(OptInToMfaAuthorizationManager optIn) {
		DefaultAuthorizationManagerFactory<Object> defaults = new DefaultAuthorizationManagerFactory<>();
		defaults.setAdditionalAuthorization(optIn);
		return defaults;
	}
	// end::authorizationManagerFactory[]

	@NullMarked
	record MyPrincipal(String username, boolean optedIn) implements UserDetails {
		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return AuthorityUtils.createAuthorityList("app");
		}

		@Override
		public @Nullable String getPassword() {
			return null;
		}

		@Override
		public String getUsername() {
			return this.username;
		}
	}

	@Bean
	UserDetailsService users() {
		return (username) -> new MyPrincipal(username, username.equals("optedin"));
	}

	@Bean
	OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler() {
		return new RedirectOneTimeTokenGenerationSuccessHandler("/ott/sent");
	}
}
