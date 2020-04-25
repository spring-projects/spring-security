/*
 * Copyright 2002-2019 the original author or authors.
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

/**
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 *  <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
 *  to <a href="https://openid.net/connect/">OpenID Connect</a>, which is supported by <code>spring-security-oauth2</code>.
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests(authorizeRequests ->
				authorizeRequests
					.antMatchers("/resources/**").permitAll()
					.anyRequest().authenticated()
			)
			.openidLogin(openidLogin ->
				openidLogin
					.loginPage("/login")
					.permitAll()
					.authenticationUserDetailsService(new CustomUserDetailsService())
					.attributeExchange(googleExchange ->
						googleExchange
							.identifierPattern("https://www.google.com/.*")
							.attribute(emailAttribute ->
								emailAttribute
									.name("email")
									.type("https://axschema.org/contact/email")
									.required(true)
							)
							.attribute(firstnameAttribute ->
								firstnameAttribute
									.name("firstname")
									.type("https://axschema.org/namePerson/first")
									.required(true)
							)
							.attribute(lastnameAttribute ->
								lastnameAttribute
									.name("lastname")
									.type("https://axschema.org/namePerson/last")
									.required(true)
							)
					)
					.attributeExchange(yahooExchange ->
						yahooExchange
							.identifierPattern(".*yahoo.com.*")
							.attribute(emailAttribute ->
								emailAttribute
									.name("email")
									.type("https://axschema.org/contact/email")
									.required(true)
							)
							.attribute(fullnameAttribute ->
								fullnameAttribute
									.name("fullname")
									.type("https://axschema.org/namePerson")
									.required(true)
							)
					)
					.attributeExchange(myopenidExchange ->
						myopenidExchange
							.identifierPattern(".*myopenid.com.*")
							.attribute(emailAttribute ->
								emailAttribute
									.name("email")
									.type("https://schema.openid.net/contact/email")
									.required(true)
							)
							.attribute(fullnameAttribute ->
									fullnameAttribute
									.name("fullname")
									.type("https://schema.openid.net/namePerson")
									.required(true)
							)
					)
			);
	}
	// @formatter:on
}
