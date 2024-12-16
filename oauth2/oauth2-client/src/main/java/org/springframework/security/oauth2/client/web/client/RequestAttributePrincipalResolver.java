/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.web.client;

import java.util.Collections;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.util.Assert;

/**
 * A strategy for resolving a {@link Authentication principal} from an intercepted request
 * using {@link ClientHttpRequest#getAttributes() attributes}.
 *
 * @author Steve Riesenberg
 * @since 6.4
 */
public class RequestAttributePrincipalResolver implements OAuth2ClientHttpRequestInterceptor.PrincipalResolver {

	private static final String PRINCIPAL_ATTR_NAME = RequestAttributePrincipalResolver.class.getName()
		.concat(".principal");

	@Override
	public Authentication resolve(HttpRequest request) {
		return (Authentication) request.getAttributes().get(PRINCIPAL_ATTR_NAME);
	}

	/**
	 * Modifies the {@link ClientHttpRequest#getAttributes() attributes} to include the
	 * {@link Authentication principal} to be used to look up the
	 * {@link OAuth2AuthorizedClient}.
	 * @param principal the {@link Authentication principal} to be used to look up the
	 * {@link OAuth2AuthorizedClient}
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> principal(Authentication principal) {
		Assert.notNull(principal, "principal cannot be null");
		return (attributes) -> attributes.put(PRINCIPAL_ATTR_NAME, principal);
	}

	/**
	 * Modifies the {@link ClientHttpRequest#getAttributes() attributes} to include the
	 * {@link Authentication principal} to be used to look up the
	 * {@link OAuth2AuthorizedClient}.
	 * @param principalName the {@code principalName} to be used to look up the
	 * {@link OAuth2AuthorizedClient}
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> principal(String principalName) {
		Assert.hasText(principalName, "principalName cannot be empty");
		Authentication principal = createAuthentication(principalName);
		return (attributes) -> attributes.put(PRINCIPAL_ATTR_NAME, principal);
	}

	private static Authentication createAuthentication(String principalName) {
		return new AbstractAuthenticationToken(Collections.emptySet()) {
			@Override
			public Object getPrincipal() {
				return principalName;
			}

			@Override
			public Object getCredentials() {
				return null;
			}
		};
	}

}
