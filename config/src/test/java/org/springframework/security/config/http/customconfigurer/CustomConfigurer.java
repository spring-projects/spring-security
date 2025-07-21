/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.http.customconfigurer;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.DefaultSecurityFilterChain;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * @author Rob Winch
 *
 */
public class CustomConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	@Value("${permitAllPattern}")
	private String permitAllPattern;

	private String loginPage = "/login";

	@SuppressWarnings("unchecked")
	@Override
	public void init(HttpSecurity http) throws Exception {
		// autowire this bean
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		context.getAutowireCapableBeanFactory().autowireBean(this);
		// @formatter:off
		http
			.authorizeHttpRequests((requests) -> requests
				.requestMatchers(pathPattern(this.permitAllPattern)).permitAll()
				.anyRequest().authenticated());
		// @formatter:on
		if (http.getConfigurer(FormLoginConfigurer.class) == null) {
			// only apply if formLogin() was not invoked by the user
			// @formatter:off
			http
				.formLogin((login) -> login
					.loginPage(this.loginPage));
			// @formatter:on
		}
	}

	public CustomConfigurer loginPage(String loginPage) {
		this.loginPage = loginPage;
		return this;
	}

	public static CustomConfigurer customConfigurer() {
		return new CustomConfigurer();
	}

}
