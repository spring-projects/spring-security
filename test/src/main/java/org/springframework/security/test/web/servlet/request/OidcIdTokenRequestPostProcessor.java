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
package org.springframework.security.test.web.servlet.request;

import java.util.Map;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.test.support.OidcIdTokenAuthenticationBuilder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.SecurityContextRequestPostProcessorSupport;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class OidcIdTokenRequestPostProcessor extends OidcIdTokenAuthenticationBuilder<OidcIdTokenRequestPostProcessor>
		implements
		RequestPostProcessor {
	ClientRegistrationPostProcessor clientRegistrationPostProcessor;
	AuthorizationRequestPostProcessor authorizationRequestPostProcessor;

	public OidcIdTokenRequestPostProcessor(final AuthorizationGrantType requestAuthorizationGrantType) {
		super(requestAuthorizationGrantType);
		clientRegistrationPostProcessor = new ClientRegistrationPostProcessor(this, clientRegistrationBuilder);
		authorizationRequestPostProcessor =
				new AuthorizationRequestPostProcessor(this, authorizationRequestBuilder, claims);
	}

	@Override
	public MockHttpServletRequest postProcessRequest(final MockHttpServletRequest request) {
		final Authentication authentication = build();
		SecurityContextRequestPostProcessorSupport.save(authentication, request);
		return request;
	}

	public ClientRegistrationPostProcessor clientRegistration() {
		return clientRegistrationPostProcessor;
	}

	public AuthorizationRequestPostProcessor authorizationRequest() {
		return authorizationRequestPostProcessor;
	}

	interface Nested {
		OidcIdTokenRequestPostProcessor and();
	}

	public final class ClientRegistrationPostProcessor
			extends
			ClientRegistrationBuilder<ClientRegistrationPostProcessor>
			implements
			OidcIdTokenRequestPostProcessor.Nested,
			RequestPostProcessor {
		private final OidcIdTokenRequestPostProcessor root;

		public ClientRegistrationPostProcessor(
				final OidcIdTokenRequestPostProcessor root,
				final ClientRegistration.Builder builder) {
			super(builder);
			this.root = root;
		}

		@Override
		public OidcIdTokenRequestPostProcessor and() {
			return root;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(final MockHttpServletRequest request) {
			return root.postProcessRequest(request);
		}
	}

	public final class AuthorizationRequestPostProcessor
			extends
			AuthorizationRequestBuilder<AuthorizationRequestPostProcessor>
			implements
			OidcIdTokenRequestPostProcessor.Nested,
			RequestPostProcessor {
		private final OidcIdTokenRequestPostProcessor root;

		public AuthorizationRequestPostProcessor(
				final OidcIdTokenRequestPostProcessor root,
				final OAuth2AuthorizationRequest.Builder builder,
				final Map<String, Object> additionalParameters) {
			super(builder, additionalParameters);
			this.root = root;
		}

		@Override
		public OidcIdTokenRequestPostProcessor and() {
			return root;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(final MockHttpServletRequest request) {
			return root.postProcessRequest(request);
		}
	}
}
