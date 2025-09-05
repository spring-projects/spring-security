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

package org.springframework.security.oauth2.server.authorization.oidc.web;

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
 * Tests for {@link OidcProviderConfigurationEndpointFilter}.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 */
public class OidcProviderConfigurationEndpointFilterTests {

	private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";

	private final OidcProviderConfigurationEndpointFilter filter = new OidcProviderConfigurationEndpointFilter();

	@AfterEach
	public void cleanup() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void setProviderConfigurationCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setProviderConfigurationCustomizer(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("providerConfigurationCustomizer cannot be null");
	}

	@Test
	public void doFilterWhenNotConfigurationRequestThenNotProcessed() throws Exception {
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
	public void doFilterWhenConfigurationRequestPostThenNotProcessed() throws Exception {
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(AuthorizationServerSettings.builder().build(), null));

		String requestUri = DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenConfigurationRequestThenConfigurationResponse() throws Exception {
		String issuer = "https://example.com";
		String authorizationEndpoint = "/oauth2/v1/authorize";
		String pushedAuthorizationRequestEndpoint = "/oauth2/v1/par";
		String tokenEndpoint = "/oauth2/v1/token";
		String jwkSetEndpoint = "/oauth2/v1/jwks";
		String userInfoEndpoint = "/userinfo";
		String logoutEndpoint = "/connect/logout";
		String tokenRevocationEndpoint = "/oauth2/v1/revoke";
		String tokenIntrospectionEndpoint = "/oauth2/v1/introspect";

		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer(issuer)
			.authorizationEndpoint(authorizationEndpoint)
			.pushedAuthorizationRequestEndpoint(pushedAuthorizationRequestEndpoint)
			.tokenEndpoint(tokenEndpoint)
			.jwkSetEndpoint(jwkSetEndpoint)
			.oidcUserInfoEndpoint(userInfoEndpoint)
			.oidcLogoutEndpoint(logoutEndpoint)
			.tokenRevocationEndpoint(tokenRevocationEndpoint)
			.tokenIntrospectionEndpoint(tokenIntrospectionEndpoint)
			.build();
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(authorizationServerSettings, null));

		String requestUri = DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		String providerConfigurationResponse = response.getContentAsString();
		assertThat(providerConfigurationResponse).contains("\"issuer\":\"https://example.com\"");
		assertThat(providerConfigurationResponse)
			.contains("\"authorization_endpoint\":\"https://example.com/oauth2/v1/authorize\"");
		assertThat(providerConfigurationResponse)
			.contains("\"pushed_authorization_request_endpoint\":\"https://example.com/oauth2/v1/par\"");
		assertThat(providerConfigurationResponse)
			.contains("\"token_endpoint\":\"https://example.com/oauth2/v1/token\"");
		assertThat(providerConfigurationResponse).contains("\"jwks_uri\":\"https://example.com/oauth2/v1/jwks\"");
		assertThat(providerConfigurationResponse).contains("\"scopes_supported\":[\"openid\"]");
		assertThat(providerConfigurationResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(providerConfigurationResponse).contains(
				"\"grant_types_supported\":[\"authorization_code\",\"client_credentials\",\"refresh_token\",\"urn:ietf:params:oauth:grant-type:device_code\",\"urn:ietf:params:oauth:grant-type:token-exchange\"]");
		assertThat(providerConfigurationResponse)
			.contains("\"revocation_endpoint\":\"https://example.com/oauth2/v1/revoke\"");
		assertThat(providerConfigurationResponse).contains(
				"\"revocation_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"tls_client_auth\",\"self_signed_tls_client_auth\"]");
		assertThat(providerConfigurationResponse)
			.contains("\"introspection_endpoint\":\"https://example.com/oauth2/v1/introspect\"");
		assertThat(providerConfigurationResponse).contains(
				"\"introspection_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"tls_client_auth\",\"self_signed_tls_client_auth\"]");
		assertThat(providerConfigurationResponse).contains("\"code_challenge_methods_supported\":[\"S256\"]");
		assertThat(providerConfigurationResponse).contains("\"tls_client_certificate_bound_access_tokens\":true");
		assertThat(providerConfigurationResponse).contains(
				"\"dpop_signing_alg_values_supported\":[\"RS256\",\"RS384\",\"RS512\",\"PS256\",\"PS384\",\"PS512\",\"ES256\",\"ES384\",\"ES512\"]");
		assertThat(providerConfigurationResponse).contains("\"subject_types_supported\":[\"public\"]");
		assertThat(providerConfigurationResponse).contains("\"id_token_signing_alg_values_supported\":[\"RS256\"]");
		assertThat(providerConfigurationResponse).contains("\"userinfo_endpoint\":\"https://example.com/userinfo\"");
		assertThat(providerConfigurationResponse)
			.contains("\"end_session_endpoint\":\"https://example.com/connect/logout\"");
		assertThat(providerConfigurationResponse).contains(
				"\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"tls_client_auth\",\"self_signed_tls_client_auth\"]");
	}

	@Test
	public void doFilterWhenAuthorizationServerSettingsWithInvalidIssuerThenThrowIllegalArgumentException() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer("https://this is an invalid URL")
			.build();
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(authorizationServerSettings, null));

		String requestUri = DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		assertThatThrownBy(() -> this.filter.doFilter(request, response, filterChain))
			.isInstanceOf(InvalidUrlException.class);
	}

}
