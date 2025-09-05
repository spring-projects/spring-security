/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AuthorizationServerContextFilter}.
 *
 * @author Joe Grandja
 */
class AuthorizationServerContextFilterTests {

	private static final String SCHEME = "https";

	private static final String HOST = "example.com";

	private static final int PORT = 8443;

	private static final String DEFAULT_ISSUER = SCHEME + "://" + HOST + ":" + PORT;

	private AuthorizationServerContextFilter filter;

	@Test
	void doFilterWhenDefaultEndpointsThenIssuerResolved() throws Exception {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();
		this.filter = new AuthorizationServerContextFilter(authorizationServerSettings);

		String issuerPath = "/issuer1";
		String issuerWithPath = DEFAULT_ISSUER.concat(issuerPath);
		Set<String> endpointUris = getEndpointUris(authorizationServerSettings);

		for (String endpointUri : endpointUris) {
			assertResolvedIssuer(issuerPath.concat(endpointUri), issuerWithPath);
		}
	}

	@Test
	void doFilterWhenCustomEndpointsThenIssuerResolved() throws Exception {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.authorizationEndpoint("/oauth2/v1/authorize")
			.deviceAuthorizationEndpoint("/oauth2/v1/device_authorization")
			.deviceVerificationEndpoint("/oauth2/v1/device_verification")
			.tokenEndpoint("/oauth2/v1/token")
			.jwkSetEndpoint("/oauth2/v1/jwks")
			.tokenRevocationEndpoint("/oauth2/v1/revoke")
			.tokenIntrospectionEndpoint("/oauth2/v1/introspect")
			.oidcClientRegistrationEndpoint("/connect/v1/register")
			.oidcUserInfoEndpoint("/v1/userinfo")
			.oidcLogoutEndpoint("/connect/v1/logout")
			.build();
		this.filter = new AuthorizationServerContextFilter(authorizationServerSettings);

		String issuerPath = "/issuer2";
		String issuerWithPath = DEFAULT_ISSUER.concat(issuerPath);
		Set<String> endpointUris = getEndpointUris(authorizationServerSettings);

		for (String endpointUri : endpointUris) {
			assertResolvedIssuer(issuerPath.concat(endpointUri), issuerWithPath);
		}
	}

	@Test
	void doFilterWhenIssuerHasMultiplePathsThenIssuerResolved() throws Exception {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();
		this.filter = new AuthorizationServerContextFilter(authorizationServerSettings);

		String issuerPath = "/path1/path2/issuer3";
		String issuerWithPath = DEFAULT_ISSUER.concat(issuerPath);
		Set<String> endpointUris = getEndpointUris(authorizationServerSettings);

		for (String endpointUri : endpointUris) {
			assertResolvedIssuer(issuerPath.concat(endpointUri), issuerWithPath);
		}
	}

	private void assertResolvedIssuer(String requestUri, String expectedIssuer) throws Exception {
		MockHttpServletRequest request = createRequest(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();

		AtomicReference<String> resolvedIssuer = new AtomicReference<>();
		FilterChain filterChain = (req, resp) -> resolvedIssuer
			.set(AuthorizationServerContextHolder.getContext().getIssuer());

		this.filter.doFilter(request, response, filterChain);

		assertThat(resolvedIssuer.get()).isEqualTo(expectedIssuer);
	}

	private static Set<String> getEndpointUris(AuthorizationServerSettings authorizationServerSettings) {
		Set<String> endpointUris = new HashSet<>();
		endpointUris.add("/.well-known/oauth-authorization-server");
		endpointUris.add("/.well-known/openid-configuration");
		for (Map.Entry<String, Object> setting : authorizationServerSettings.getSettings().entrySet()) {
			if (setting.getKey().endsWith("-endpoint")) {
				endpointUris.add((String) setting.getValue());
			}
		}
		return endpointUris;
	}

	private static MockHttpServletRequest createRequest(String requestUri) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI(requestUri);
		request.setScheme(SCHEME);
		request.setServerName(HOST);
		request.setServerPort(PORT);
		return request;
	}

}
