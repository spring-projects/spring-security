package org.springframework.security.samples.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// @formatter:off
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth)
			throws Exception {
		auth.
			inMemoryAuthentication()
				.withUser("dianne").password("password").roles("USER").and()
				.withUser("rod").password("password").roles("USER","ADMIN").and()
				.withUser("scott").password("password").roles("USER");
	}
	// @formatter:on

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.x509();
	}
	// @formatter:on
}
