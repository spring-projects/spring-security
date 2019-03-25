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
package org.springframework.security.test.context.support.oauth2.request;

import java.util.Map;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.test.context.support.oauth2.support.OidcIdSupport;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public final class ClientRegistrationPostProcessor
		implements
		OidcIdTokenRequestPostProcessor.Nested,
		RequestPostProcessor {
	private final ClientRegistration.Builder delegate;
	private final OidcIdTokenRequestPostProcessor root;

	public ClientRegistrationPostProcessor(final OidcIdTokenRequestPostProcessor root, final String registrationID) {
		this.delegate = ClientRegistration.withRegistrationId(registrationID);
		this.root = root;
	}

	public static ClientRegistrationPostProcessor withDefaults(final OidcIdTokenRequestPostProcessor root) {
		return new ClientRegistrationPostProcessor(root, OidcIdSupport.CLIENT_REGISTRATION_ID)
				.authorizationGrantType(new AuthorizationGrantType(OidcIdSupport.CLIENT_GRANT_TYPE))
				.clientId(OidcIdSupport.CLIENT_ID)
				.tokenUri(OidcIdSupport.CLIENT_TOKEN_URI);
	}

	@Override
	public OidcIdTokenRequestPostProcessor and() {
		return root;
	}

	@Override
	public MockHttpServletRequest postProcessRequest(final MockHttpServletRequest request) {
		return root.postProcessRequest(request);
	}

	public ClientRegistrationPostProcessor authorizationGrantType(final AuthorizationGrantType authorizationGrantType) {
		delegate.authorizationGrantType(authorizationGrantType);
		return this;
	}

	public ClientRegistrationPostProcessor authorizationUri(final String authorizationUri) {
		delegate.authorizationUri(authorizationUri);
		return this;
	}

	ClientRegistration.Builder builder() {
		return delegate;
	}

	public ClientRegistrationPostProcessor
			clientAuthenticationMethod(final ClientAuthenticationMethod clientAuthenticationMethod) {
		delegate.clientAuthenticationMethod(clientAuthenticationMethod);
		return this;
	}

	public ClientRegistrationPostProcessor clientId(final String clientId) {
		delegate.clientId(clientId);
		return this;
	}

	public ClientRegistrationPostProcessor clientName(final String clientName) {
		delegate.clientName(clientName);
		return this;
	}

	public ClientRegistrationPostProcessor clientSecret(final String clientSecret) {
		delegate.clientSecret(clientSecret);
		return this;
	}

	public ClientRegistrationPostProcessor jwkSetUri(final String jwkSetUri) {
		delegate.jwkSetUri(jwkSetUri);
		return this;
	}

	public ClientRegistrationPostProcessor
			providerConfigurationMetadata(final Map<String, Object> configurationMetadata) {
		delegate.providerConfigurationMetadata(configurationMetadata);
		return this;
	}

	public ClientRegistrationPostProcessor redirectUriTemplate(final String redirectUriTemplate) {
		delegate.redirectUriTemplate(redirectUriTemplate);
		return this;
	}

	public ClientRegistrationPostProcessor registrationId(final String registrationId) {
		delegate.registrationId(registrationId);
		return this;
	}

	public ClientRegistrationPostProcessor tokenUri(final String tokenUri) {
		delegate.tokenUri(tokenUri);
		return this;
	}

	public ClientRegistrationPostProcessor
			userInfoAuthenticationMethod(final AuthenticationMethod userInfoAuthenticationMethod) {
		delegate.userInfoAuthenticationMethod(userInfoAuthenticationMethod);
		return this;
	}
}