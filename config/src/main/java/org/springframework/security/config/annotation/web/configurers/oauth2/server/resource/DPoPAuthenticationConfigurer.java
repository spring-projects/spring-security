/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.resource;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.DPoPAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.DPoPRequestMatcher;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Demonstrating Proof of Possession
 * (DPoP) support.
 *
 * @author Joe Grandja
 * @author Max Batischev
 * @since 6.5
 * @see DPoPAuthenticationProvider
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449
 * OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>
 */
public final class DPoPAuthenticationConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<DPoPAuthenticationConfigurer<B>, B> {

	private RequestMatcher requestMatcher;

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler;

	private AuthenticationFailureHandler authenticationFailureHandler;

	@Override
	public void configure(B http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		http.authenticationProvider(new DPoPAuthenticationProvider(authenticationManager));
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager,
				getAuthenticationConverter());
		authenticationFilter.setRequestMatcher(getRequestMatcher());
		authenticationFilter.setSuccessHandler(getAuthenticationSuccessHandler());
		authenticationFilter.setFailureHandler(getAuthenticationFailureHandler());
		authenticationFilter.setSecurityContextRepository(new RequestAttributeSecurityContextRepository());
		authenticationFilter = postProcess(authenticationFilter);
		http.addFilter(authenticationFilter);
	}

	/**
	 * Sets the {@link RequestMatcher} to use.
	 * @param requestMatcher
	 * @since 7.0
	 */
	public DPoPAuthenticationConfigurer<B> requestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationConverter} to use.
	 * @param authenticationConverter
	 * @since 7.0
	 */
	public DPoPAuthenticationConfigurer<B> authenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} to use.
	 * @param failureHandler
	 * @since 7.0
	 */
	public DPoPAuthenticationConfigurer<B> failureHandler(AuthenticationFailureHandler failureHandler) {
		Assert.notNull(failureHandler, "failureHandler cannot be null");
		this.authenticationFailureHandler = failureHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} to use.
	 * @param successHandler
	 * @since 7.0
	 */
	public DPoPAuthenticationConfigurer<B> successHandler(AuthenticationSuccessHandler successHandler) {
		Assert.notNull(successHandler, "successHandler cannot be null");
		this.authenticationSuccessHandler = successHandler;
		return this;
	}

	private RequestMatcher getRequestMatcher() {
		if (this.requestMatcher == null) {
			this.requestMatcher = new DPoPRequestMatcher();
		}
		return this.requestMatcher;
	}

	private AuthenticationConverter getAuthenticationConverter() {
		if (this.authenticationConverter == null) {
			this.authenticationConverter = new DPoPAuthenticationConverter();
		}
		return this.authenticationConverter;
	}

	private AuthenticationSuccessHandler getAuthenticationSuccessHandler() {
		if (this.authenticationSuccessHandler == null) {
			this.authenticationSuccessHandler = (request, response, authentication) -> {
				// No-op - will continue on filter chain
			};
		}
		return this.authenticationSuccessHandler;
	}

	private AuthenticationFailureHandler getAuthenticationFailureHandler() {
		if (this.authenticationFailureHandler == null) {
			this.authenticationFailureHandler = new AuthenticationEntryPointFailureHandler(
					new DPoPAuthenticationEntryPoint());
		}
		return this.authenticationFailureHandler;
	}

}
