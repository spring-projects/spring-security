/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * {@link Configuration} that exposes the {@link HttpSecurity} bean.
 *
 * @author Eleftheria Stein
 * @since 5.4
 */
@Configuration(proxyBeanMethods = false)
class HttpSecurityConfiguration {
	private static final String BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration.";
	private static final String HTTPSECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

	private ObjectPostProcessor<Object> objectPostProcessor;

	private AuthenticationManager authenticationManager;

	private AuthenticationConfiguration authenticationConfiguration;

	private ApplicationContext context;

	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	@Autowired(required = false)
	void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Autowired
	public void setAuthenticationConfiguration(
			AuthenticationConfiguration authenticationConfiguration) {
		this.authenticationConfiguration = authenticationConfiguration;
	}

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.context = context;
	}

	@Bean(HTTPSECURITY_BEAN_NAME)
	@Scope("prototype")
	public HttpSecurity httpSecurity() throws Exception {
		WebSecurityConfigurerAdapter.LazyPasswordEncoder passwordEncoder =
				new WebSecurityConfigurerAdapter.LazyPasswordEncoder(this.context);

		AuthenticationManagerBuilder authenticationBuilder =
				new WebSecurityConfigurerAdapter.DefaultPasswordEncoderAuthenticationManagerBuilder(this.objectPostProcessor, passwordEncoder);
		authenticationBuilder.parentAuthenticationManager(authenticationManager());

		HttpSecurity http = new HttpSecurity(objectPostProcessor, authenticationBuilder, createSharedObjects());
		http
				.csrf(withDefaults())
				.addFilter(new WebAsyncManagerIntegrationFilter())
				.exceptionHandling(withDefaults())
				.headers(withDefaults())
				.sessionManagement(withDefaults())
				.securityContext(withDefaults())
				.requestCache(withDefaults())
				.anonymous(withDefaults())
				.servletApi(withDefaults())
				.logout(withDefaults())
				.apply(new DefaultLoginPageConfigurer<>());

		return http;
	}

	private AuthenticationManager authenticationManager() throws Exception {
		if (this.authenticationManager != null) {
			return this.authenticationManager;
		} else {
			return this.authenticationConfiguration.getAuthenticationManager();
		}
	}

	private Map<Class<?>, Object> createSharedObjects() {
		Map<Class<?>, Object> sharedObjects = new HashMap<>();
		sharedObjects.put(ApplicationContext.class, context);
		return sharedObjects;
	}
}
