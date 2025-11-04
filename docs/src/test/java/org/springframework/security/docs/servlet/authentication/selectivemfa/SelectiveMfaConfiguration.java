package org.springframework.security.docs.servlet.authentication.selectivemfa;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;

@EnableWebSecurity
// tag::enable-mfa[]
@EnableMultiFactorAuthentication(authorities = {})
// end::enable-mfa[]
@Configuration(proxyBeanMethods = false)
class SelectiveMfaConfiguration {

	// tag::httpSecurity[]
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		// <1>
		var mfa = AuthorizationManagerFactories.multiFactor()
			.requireFactors(
				FactorGrantedAuthority.PASSWORD_AUTHORITY,
				FactorGrantedAuthority.OTT_AUTHORITY
			)
			.build();
		http
			.authorizeHttpRequests((authorize) -> authorize
				// <2>
				.requestMatchers("/admin/**").access(mfa.hasRole("ADMIN"))
				// <3>
				.requestMatchers("/user/settings/**").access(mfa.authenticated())
				// <4>
				.anyRequest().authenticated()
			)
			// <5>
			.formLogin(Customizer.withDefaults())
			.oneTimeTokenLogin(Customizer.withDefaults());
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
