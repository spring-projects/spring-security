package org.springframework.security.docs.servlet.authentication.validduration;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.config.Customizer;
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
@Configuration(proxyBeanMethods = false)
class ValidDurationConfiguration {

	// tag::httpSecurity[]
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		// <1>
		var passwordIn30m = AuthorizationManagerFactories.multiFactor()
			.requireFactor( (factor) -> factor
				.passwordAuthority()
				.validDuration(Duration.ofMinutes(30))
			)
			.build();
		// <2>
		var passwordInHour = AuthorizationManagerFactories.multiFactor()
			.requireFactor( (factor) -> factor
				.passwordAuthority()
				.validDuration(Duration.ofHours(1))
			)
			.build();
		http
			.authorizeHttpRequests((authorize) -> authorize
				// <3>
				.requestMatchers("/admin/**").access(passwordIn30m.hasRole("ADMIN"))
				// <4>
				.requestMatchers("/user/settings/**").access(passwordInHour.authenticated())
				// <5>
				.anyRequest().authenticated()
			)
			// <6>
			.formLogin(Customizer.withDefaults());
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
}
