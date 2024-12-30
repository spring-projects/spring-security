/*
 * Copyright 2019-2024 the original author or authors.
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

package org.springframework.security.config.annotation.rsocket;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author Rob Winch
 * @since 5.2
 */
@Configuration(proxyBeanMethods = false)
class RSocketSecurityConfiguration {

	private static final String BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.rsocket.RSocketSecurityConfiguration.";

	private static final String RSOCKET_SECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "rsocketSecurity";

	private ReactiveAuthenticationManager authenticationManager;

	private ReactiveUserDetailsService reactiveUserDetailsService;

	private PasswordEncoder passwordEncoder;

	private ObjectPostProcessor<ReactiveAuthenticationManager> postProcessor = ObjectPostProcessor.identity();

	@Autowired(required = false)
	void setAuthenticationManager(ReactiveAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Autowired(required = false)
	void setUserDetailsService(ReactiveUserDetailsService userDetailsService) {
		this.reactiveUserDetailsService = userDetailsService;
	}

	@Autowired(required = false)
	void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Autowired(required = false)
	void setAuthenticationManagerPostProcessor(
			Map<String, ObjectPostProcessor<ReactiveAuthenticationManager>> postProcessors) {
		if (postProcessors.size() == 1) {
			this.postProcessor = postProcessors.values().iterator().next();
		}
		this.postProcessor = postProcessors.get("rSocketAuthenticationManagerPostProcessor");
	}

	@Bean(name = RSOCKET_SECURITY_BEAN_NAME)
	@Scope("prototype")
	RSocketSecurity rsocketSecurity(ApplicationContext context) {
		RSocketSecurity security = new RSocketSecurity().authenticationManager(authenticationManager());
		security.setApplicationContext(context);
		return security;
	}

	private ReactiveAuthenticationManager authenticationManager() {
		if (this.authenticationManager != null) {
			return this.authenticationManager;
		}
		if (this.reactiveUserDetailsService != null) {
			UserDetailsRepositoryReactiveAuthenticationManager manager = new UserDetailsRepositoryReactiveAuthenticationManager(
					this.reactiveUserDetailsService);
			if (this.passwordEncoder != null) {
				manager.setPasswordEncoder(this.passwordEncoder);
			}
			return this.postProcessor.postProcess(manager);
		}
		return null;
	}

}
