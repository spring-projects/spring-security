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

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.endpoint.AuthorizationRequestUriBuilder;
import org.springframework.util.Assert;

/**
 * A security configurer for the Implicit Grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public final class ImplicitGrantConfigurer<B extends HttpSecurityBuilder<B>> extends
	AbstractHttpConfigurer<ImplicitGrantConfigurer<B>, B> {

	private String authorizationRequestBaseUri;
	private AuthorizationRequestUriBuilder authorizationRequestUriBuilder;

	public ImplicitGrantConfigurer<B> authorizationRequestBaseUri(String authorizationRequestBaseUri) {
		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		this.authorizationRequestBaseUri = authorizationRequestBaseUri;
		return this;
	}

	public ImplicitGrantConfigurer<B> authorizationRequestUriBuilder(AuthorizationRequestUriBuilder authorizationRequestUriBuilder) {
		Assert.notNull(authorizationRequestUriBuilder, "authorizationRequestUriBuilder cannot be null");
		this.authorizationRequestUriBuilder = authorizationRequestUriBuilder;
		return this;
	}

	public ImplicitGrantConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	@Override
	public void configure(B http) throws Exception {
		AuthorizationRequestRedirectFilter authorizationRequestFilter = new AuthorizationRequestRedirectFilter(
			this.getAuthorizationRequestBaseUri(), this.getClientRegistrationRepository());
		if (this.authorizationRequestUriBuilder != null) {
			authorizationRequestFilter.setAuthorizationRequestUriBuilder(this.authorizationRequestUriBuilder);
		}
		http.addFilter(this.postProcess(authorizationRequestFilter));
	}

	private String getAuthorizationRequestBaseUri() {
		return this.authorizationRequestBaseUri != null ?
			this.authorizationRequestBaseUri :
			AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
	}

	private ClientRegistrationRepository getClientRegistrationRepository() {
		ClientRegistrationRepository clientRegistrationRepository = this.getBuilder().getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = this.getClientRegistrationRepositoryBean();
			this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private ClientRegistrationRepository getClientRegistrationRepositoryBean() {
		return this.getBuilder().getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
	}
}
