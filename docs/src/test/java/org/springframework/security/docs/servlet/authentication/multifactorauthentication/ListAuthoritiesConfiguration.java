package org.springframework.security.docs.servlet.authentication.multifactorauthentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthorities;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class ListAuthoritiesConfiguration {

	// tag::httpSecurity[]
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().hasAllAuthorities(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY, GrantedAuthorities.FACTOR_OTT_AUTHORITY) // <1>
			)
			.formLogin(Customizer.withDefaults())
			.oneTimeTokenLogin(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}
	// end::httpSecurity[]

	@Bean
	UserDetailsService users() {
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
