/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.config.annotation.web.reactive;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepository;
import org.springframework.security.authentication.UserDetailsRepositoryAuthenticationManager;
import org.springframework.security.config.web.server.HttpSecurity;
import org.springframework.security.web.reactive.result.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.server.context.WebSessionSecurityContextRepository;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

import static org.springframework.security.config.web.server.HttpSecurity.http;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Configuration
public class WebFluxSecurityConfiguration implements WebFluxConfigurer {
	@Autowired(required = false)
	private ReactiveAdapterRegistry adapterRegistry = new ReactiveAdapterRegistry();

	@Autowired(required = false)
	private ReactiveAuthenticationManager authenticationManager;

	@Autowired(required = false)
	private UserDetailsRepository userDetailsRepository;

	@Override
	public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
		configurer.addCustomResolver(authenticationPrincipalArgumentResolver());
	}

	@Bean
	public AuthenticationPrincipalArgumentResolver authenticationPrincipalArgumentResolver() {
		return new AuthenticationPrincipalArgumentResolver(adapterRegistry);
	}

	@Bean
	public HttpSecurity httpSecurity() {
		HttpSecurity http = http();
		http.authenticationManager(authenticationManager());
		http.securityContextRepository(new WebSessionSecurityContextRepository());
		return http;
	}

	private ReactiveAuthenticationManager authenticationManager() {
		if(authenticationManager != null) {
			return authenticationManager;
		}
		if(userDetailsRepository != null) {
			return new UserDetailsRepositoryAuthenticationManager(userDetailsRepository);
		}
		return null;
	}
}
