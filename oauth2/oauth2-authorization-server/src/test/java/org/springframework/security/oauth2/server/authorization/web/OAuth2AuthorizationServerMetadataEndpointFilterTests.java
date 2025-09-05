/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.util.InvalidUrlException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2AuthorizationServerMetadataEndpointFilter}.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 */
public class OAuth2AuthorizationServerMetadataEndpointFilterTests {

	private static final String DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI = "/.well-known/oauth-authorization-server";

	private final OAuth2AuthorizationServerMetadataEndpointFilter filter = new OAuth2AuthorizationServerMetadataEndpointFilter();

	@AfterEach
	public void cleanup() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void setAuthorizationServerMetadataCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthorizationServerMetadataCustomizer(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorizationServerMetadataCustomizer cannot be null");
	}

	@Test
	public void doFilterWhenNotAuthorizationServerMetadataRequestThenNotProcessed() throws Exception {
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(AuthorizationServerSettings.builder().build(), null));

		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationServerMetadataRequestPostThenNotProcessed() throws Exception {
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(AuthorizationServerSettings.builder().build(), null));

		String requestUri = DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationServerMetadataRequestThenMetadataResponse() throws Exception {
		String issuer = "https://example.com";
		String authorizationEndpoint = "/oauth2/v1/authorize";
		String pushedAuthorizationRequestEndpoint = "/oauth2/v1/par";
		String tokenEndpoint = "/oauth2/v1/token";
		String jwkSetEndpoint = "/oauth2/v1/jwks";
		String tokenRevocationEndpoint = "/oauth2/v1/revoke";
		String tokenIntrospectionEndpoint = "/oauth2/v1/introspect";

		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer(issuer)
			.authorizationEndpoint(authorizationEndpoint)
			.pushedAuthorizationRequestEndpoint(pushedAuthorizationRequestEndpoint)
			.tokenEndpoint(tokenEndpoint)
			.jwkSetEndpoint(jwkSetEndpoint)
			.tokenRevocationEndpoint(tokenRevocationEndpoint)
			.tokenIntrospectionEndpoint(tokenIntrospectionEndpoint)
			.build();
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(authorizationServerSettings, null));

		String requestUri = DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		String authorizationServerMetadataResponse = response.getContentAsString();
		assertThat(authorizationServerMetadataResponse).contains("\"issuer\":\"https://example.com\"");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"authorization_endpoint\":\"https://example.com/oauth2/v1/authorize\"");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"pushed_authorization_request_endpoint\":\"https://example.com/oauth2/v1/par\"");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"token_endpoint\":\"https://example.com/oauth2/v1/token\"");
		assertThat(authorizationServerMetadataResponse).contains(
				"\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"tls_client_auth\",\"self_signed_tls_client_auth\"]");
		assertThat(authorizationServerMetadataResponse).contains("\"jwks_uri\":\"https://example.com/oauth2/v1/jwks\"");
		assertThat(authorizationServerMetadataResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(authorizationServerMetadataResponse).contains(
				"\"grant_types_supported\":[\"authorization_code\",\"client_credentials\",\"refresh_token\",\"urn:ietf:params:oauth:grant-type:device_code\",\"urn:ietf:params:oauth:grant-type:token-exchange\"]");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"revocation_endpoint\":\"https://example.com/oauth2/v1/revoke\"");
		assertThat(authorizationServerMetadataResponse).contains(
				"\"revocation_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"tls_client_auth\",\"self_signed_tls_client_auth\"]");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"introspection_endpoint\":\"https://example.com/oauth2/v1/introspect\"");
		assertThat(authorizationServerMetadataResponse).contains(
				"\"introspection_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"tls_client_auth\",\"self_signed_tls_client_auth\"]");
		assertThat(authorizationServerMetadataResponse).contains("\"code_challenge_methods_supported\":[\"S256\"]");
		assertThat(authorizationServerMetadataResponse).contains("\"tls_client_certificate_bound_access_tokens\":true");
		assertThat(authorizationServerMetadataResponse).contains(
				"\"dpop_signing_alg_values_supported\":[\"RS256\",\"RS384\",\"RS512\",\"PS256\",\"PS384\",\"PS512\",\"ES256\",\"ES384\",\"ES512\"]");
	}

	@Test
	public void doFilterWhenAuthorizationServerSettingsWithInvalidIssuerThenThrowIllegalArgumentException() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer("https://this is an invalid URL")
			.build();
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(authorizationServerSettings, null));

		String requestUri = DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		assertThatThrownBy(() -> this.filter.doFilter(request, response, filterChain))
			.isInstanceOf(InvalidUrlException.class);
	}

}
