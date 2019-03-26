/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.samples.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.samples.security.CustomUserDetailsService;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/resources/**").permitAll()
				.anyRequest().authenticated()
				.and()
			.openidLogin()
				.loginPage("/login")
				.permitAll()
				.authenticationUserDetailsService(new CustomUserDetailsService())
				.attributeExchange("https://www.google.com/.*")
					.attribute("email")
						.type("https://axschema.org/contact/email")
						.required(true)
						.and()
					.attribute("firstname")
						.type("https://axschema.org/namePerson/first")
						.required(true)
						.and()
					.attribute("lastname")
						.type("https://axschema.org/namePerson/last")
						.required(true)
						.and()
					.and()
				.attributeExchange(".*yahoo.com.*")
					.attribute("email")
						.type("https://axschema.org/contact/email")
						.required(true)
						.and()
					.attribute("fullname")
						.type("https://axschema.org/namePerson")
						.required(true)
						.and()
					.and()
				.attributeExchange(".*myopenid.com.*")
					.attribute("email")
						.type("https://schema.openid.net/contact/email")
						.required(true)
						.and()
					.attribute("fullname")
						.type("https://schema.openid.net/namePerson")
						.required(true);
	}
	// @formatter:on
}
