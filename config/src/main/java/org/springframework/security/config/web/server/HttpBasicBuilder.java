/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.web.server;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.HttpBasicAuthenticationConverter;
import org.springframework.security.web.server.authentication.DefaultAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.www.HttpBasicAuthenticationEntryPoint;
import org.springframework.security.web.server.context.SecurityContextRepository;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class HttpBasicBuilder {
	private ReactiveAuthenticationManager authenticationManager;

	private SecurityContextRepository securityContextRepository;

	private AuthenticationEntryPoint entryPoint = new HttpBasicAuthenticationEntryPoint();

	public HttpBasicBuilder authenticationManager(ReactiveAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	public HttpBasicBuilder securityContextRepository(SecurityContextRepository securityContextRepository) {
		this.securityContextRepository = securityContextRepository;
		return this;
	}

	public AuthenticationWebFilter build() {
		AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(authenticationManager);
		authenticationFilter.setEntryPoint(entryPoint);
		authenticationFilter.setAuthenticationConverter(new HttpBasicAuthenticationConverter());
		if(securityContextRepository != null) {
			DefaultAuthenticationSuccessHandler handler = new DefaultAuthenticationSuccessHandler();
			handler.setSecurityContextRepository(securityContextRepository);
			authenticationFilter.setAuthenticationSuccessHandler(handler);
		}
		return authenticationFilter;
	}
}
