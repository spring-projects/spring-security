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
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeRequestRedirectFilter;
import org.springframework.security.oauth2.client.authentication.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.authentication.DefaultAuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

/**
 * @author Joe Grandja
 */
final class AuthorizationCodeRequestRedirectFilterConfigurer<B extends HttpSecurityBuilder<B>> extends
		AbstractHttpConfigurer<AuthorizationCodeRequestRedirectFilterConfigurer<B>, B> {

	private AuthorizationRequestUriBuilder authorizationRequestBuilder;

	AuthorizationCodeRequestRedirectFilterConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	AuthorizationCodeRequestRedirectFilterConfigurer<B> authorizationRequestBuilder(AuthorizationRequestUriBuilder authorizationRequestBuilder) {
		Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
		this.authorizationRequestBuilder = authorizationRequestBuilder;
		return this;
	}

	@Override
	public void configure(B http) throws Exception {
		AuthorizationCodeRequestRedirectFilter filter = new AuthorizationCodeRequestRedirectFilter(
				OAuth2LoginConfigurer.getClientRegistrationRepository(this.getBuilder()),
				this.getAuthorizationRequestBuilder());
		http.addFilter(this.postProcess(filter));
	}

	private AuthorizationRequestUriBuilder getAuthorizationRequestBuilder() {
		if (this.authorizationRequestBuilder == null) {
			this.authorizationRequestBuilder = new DefaultAuthorizationRequestUriBuilder();
		}
		return this.authorizationRequestBuilder;
	}
}
