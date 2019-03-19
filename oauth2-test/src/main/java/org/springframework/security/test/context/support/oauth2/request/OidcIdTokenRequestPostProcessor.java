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
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.test.context.support.oauth2.support.OidcIdSupport;
import org.springframework.security.test.web.servlet.request.SecurityContextRequestPostProcessorSupport;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class OidcIdTokenRequestPostProcessor
		extends
		AbstractOAuth2RequestPostProcessor<OidcIdTokenRequestPostProcessor> {
	String nameAttributeKey = OidcIdSupport.DEFAULT_NAME_KEY;
	ClientRegistrationPostProcessor clientRegistration;
	OAuth2AuthorizationRequestPostProcessor authorizationRequest;

	public OidcIdTokenRequestPostProcessor(final AuthorizationGrantType authorizationGrantType) {
		super(OidcIdSupport.DEFAULT_AUTH_NAME, OidcIdSupport.DEFAULT_AUTHORITIES);
		clientRegistration = ClientRegistrationPostProcessor.withDefaults(this);
		authorizationRequest = OAuth2AuthorizationRequestPostProcessor.withDefaults(this, authorizationGrantType);
	}

	@Override
	public MockHttpServletRequest postProcessRequest(final MockHttpServletRequest request) {
		final OidcIdSupport support = new OidcIdSupport(authorities, scopes, attributes);
		final Authentication authentication = support
				.authentication(name, nameAttributeKey, clientRegistration.builder(), authorizationRequest.builder());
		SecurityContextRequestPostProcessorSupport.createSecurityContext(authentication, request);
		return request;
	}

	public OidcIdTokenRequestPostProcessor nameAttributeKey(final String nameAttributeKey) {
		this.nameAttributeKey = nameAttributeKey;
		return this;
	}

	public OidcIdTokenRequestPostProcessor claims(final Map<String, Object> additionalClaims) {
		return attributes(additionalClaims);
	}

	public OidcIdTokenRequestPostProcessor claim(final String name, final Object value) {
		return attribute(name, value);
	}

	public ClientRegistrationPostProcessor clientRegistration() {
		return clientRegistration;
	}

	public OAuth2AuthorizationRequestPostProcessor authorizationRequest() {
		return authorizationRequest;
	}

	interface Nested {
		OidcIdTokenRequestPostProcessor and();
	}

}
