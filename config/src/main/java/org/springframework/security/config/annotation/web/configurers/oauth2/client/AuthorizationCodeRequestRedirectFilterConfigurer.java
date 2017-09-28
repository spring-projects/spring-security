/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationCodeRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.web.DefaultAuthorizationRequestUriBuilder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestVariablesExtractor;
import org.springframework.util.Assert;

/**
 * @author Joe Grandja
 */
final class AuthorizationCodeRequestRedirectFilterConfigurer<H extends HttpSecurityBuilder<H>, R extends RequestMatcher & RequestVariablesExtractor> extends
		AbstractHttpConfigurer<AuthorizationCodeRequestRedirectFilterConfigurer<H, R>, H> {

	private R authorizationRequestMatcher;
	private AuthorizationRequestUriBuilder authorizationRequestBuilder;

	AuthorizationCodeRequestRedirectFilterConfigurer<H, R> authorizationRequestMatcher(R authorizationRequestMatcher) {
		Assert.notNull(authorizationRequestMatcher, "authorizationRequestMatcher cannot be null");
		this.authorizationRequestMatcher = authorizationRequestMatcher;
		return this;
	}

	AuthorizationCodeRequestRedirectFilterConfigurer<H, R> authorizationRequestBuilder(AuthorizationRequestUriBuilder authorizationRequestBuilder) {
		Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
		this.authorizationRequestBuilder = authorizationRequestBuilder;
		return this;
	}

	AuthorizationCodeRequestRedirectFilterConfigurer<H, R> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	R getAuthorizationRequestMatcher() {
		return this.authorizationRequestMatcher;
	}

	@Override
	public void configure(H http) throws Exception {
		AuthorizationCodeRequestRedirectFilter filter = new AuthorizationCodeRequestRedirectFilter(
				OAuth2LoginConfigurer.getClientRegistrationRepository(this.getBuilder()));
		if (this.authorizationRequestMatcher != null) {
			filter.setAuthorizationRequestMatcher(this.authorizationRequestMatcher);
		}
		if (this.authorizationRequestBuilder != null) {
			filter.setAuthorizationUriBuilder(this.authorizationRequestBuilder);
		}
		http.addFilter(this.postProcess(filter));
	}

	private AuthorizationRequestUriBuilder getAuthorizationRequestBuilder() {
		if (this.authorizationRequestBuilder == null) {
			this.authorizationRequestBuilder = new DefaultAuthorizationRequestUriBuilder();
		}
		return this.authorizationRequestBuilder;
	}
}
