package org.springframework.security.samples.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableWebSecurity
public class SecurityConfig {
	// @formatter:off
	@Autowired
	public void configureGlobal(
			AuthenticationManagerBuilder auth) throws Exception {
		auth
			.ldapAuthentication()
				.userDnPatterns("uid={0},ou=people")
				.groupSearchBase("ou=groups");
	}
	// @formatter:on
}