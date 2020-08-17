/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.client.registration;

import java.util.Arrays;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Rob Winch
 * @author Rafiullah Hamedy
 * @since 5.1
 */
public class ClientRegistrationsTest {

	/**
	 * Contains all optional parameters that are found in ClientRegistration
	 */
	private static final String DEFAULT_RESPONSE =
			"{\n"
			+ "    \"authorization_endpoint\": \"https://example.com/o/oauth2/v2/auth\", \n"
			+ "    \"claims_supported\": [\n"
			+ "        \"aud\", \n"
			+ "        \"email\", \n"
			+ "        \"email_verified\", \n"
			+ "        \"exp\", \n"
			+ "        \"family_name\", \n"
			+ "        \"given_name\", \n"
			+ "        \"iat\", \n"
			+ "        \"iss\", \n"
			+ "        \"locale\", \n"
			+ "        \"name\", \n"
			+ "        \"picture\", \n"
			+ "        \"sub\"\n"
			+ "    ], \n"
			+ "    \"code_challenge_methods_supported\": [\n"
			+ "        \"plain\", \n"
			+ "        \"S256\"\n"
			+ "    ], \n"
			+ "    \"id_token_signing_alg_values_supported\": [\n"
			+ "        \"RS256\"\n"
			+ "    ], \n"
			+ "    \"issuer\": \"https://example.com\", \n"
			+ "    \"jwks_uri\": \"https://example.com/oauth2/v3/certs\", \n"
			+ "    \"response_types_supported\": [\n"
			+ "        \"code\", \n"
			+ "        \"token\", \n"
			+ "        \"id_token\", \n"
			+ "        \"code token\", \n"
			+ "        \"code id_token\", \n"
			+ "        \"token id_token\", \n"
			+ "        \"code token id_token\", \n"
			+ "        \"none\"\n"
			+ "    ], \n"
			+ "    \"revocation_endpoint\": \"https://example.com/o/oauth2/revoke\", \n"
			+ "    \"scopes_supported\": [\n"
			+ "        \"openid\", \n"
			+ "        \"email\", \n"
			+ "        \"profile\"\n"
			+ "    ], \n"
			+ "    \"subject_types_supported\": [\n"
			+ "        \"public\"\n"
			+ "    ], \n"
			+ "    \"grant_types_supported\" : [\"authorization_code\"], \n"
			+ "    \"token_endpoint\": \"https://example.com/oauth2/v4/token\", \n"
			+ "    \"token_endpoint_auth_methods_supported\": [\n"
			+ "        \"client_secret_post\", \n"
			+ "        \"client_secret_basic\", \n"
			+ "        \"none\"\n"
			+ "    ], \n"
			+ "    \"userinfo_endpoint\": \"https://example.com/oauth2/v3/userinfo\"\n"
			+ "}";

	private MockWebServer server;

	private ObjectMapper mapper = new ObjectMapper();

	private Map<String, Object> response;

	private String issuer;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.response = this.mapper.readValue(DEFAULT_RESPONSE, new TypeReference<Map<String, Object>>(){});
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void issuerWhenAllInformationThenSuccess() throws Exception {
		ClientRegistration registration = registration("").build();
		ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
		assertIssuerMetadata(registration, provider);
		assertThat(provider.getUserInfoEndpoint().getUri()).isEqualTo("https://example.com/oauth2/v3/userinfo");
	}

	/**
	 *
	 * Test compatibility with OpenID v1 discovery endpoint by making a
	 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID Provider
	 * Configuration Request</a> as highlighted <a href="https://tools.ietf.org/html/rfc8414#section-5">
	 * Compatibility Notes</a> of <a href="https://tools.ietf.org/html/rfc8414">RFC 8414</a> specification.
	 */
	@Test
	public void issuerWhenOidcFallbackAllInformationThenSuccess() throws Exception {
		ClientRegistration registration = registrationOidcFallback("issuer1", null).build();
		ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
		assertIssuerMetadata(registration, provider);
		assertThat(provider.getUserInfoEndpoint().getUri()).isEqualTo("https://example.com/oauth2/v3/userinfo");
	}

	@Test
	public void issuerWhenOAuth2AllInformationThenSuccess() throws Exception {
		ClientRegistration registration = registrationOAuth2("", null).build();
		ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
		assertIssuerMetadata(registration, provider);
	}

	private void assertIssuerMetadata(ClientRegistration registration,
			ClientRegistration.ProviderDetails provider) {
		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registration.getRegistrationId()).isEqualTo(this.server.getHostName());
		assertThat(registration.getClientName()).isEqualTo(this.issuer);
		assertThat(registration.getScopes()).isNull();
		assertThat(provider.getAuthorizationUri()).isEqualTo("https://example.com/o/oauth2/v2/auth");
		assertThat(provider.getTokenUri()).isEqualTo("https://example.com/oauth2/v4/token");
		assertThat(provider.getJwkSetUri()).isEqualTo("https://example.com/oauth2/v3/certs");
		assertThat(provider.getIssuerUri()).isEqualTo(this.issuer);
		assertThat(provider.getConfigurationMetadata()).containsKeys("authorization_endpoint", "claims_supported",
				"code_challenge_methods_supported", "id_token_signing_alg_values_supported", "issuer", "jwks_uri",
				"response_types_supported", "revocation_endpoint", "scopes_supported", "subject_types_supported",
				"grant_types_supported", "token_endpoint", "token_endpoint_auth_methods_supported", "userinfo_endpoint");
	}

	// gh-7512
	@Test
	public void issuerWhenResponseMissingJwksUriThenThrowsIllegalArgumentException() throws Exception {
		this.response.remove("jwks_uri");
		assertThatThrownBy(() -> registration("").build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("The public JWK set URI must not be null");
	}

	// gh-7512
	@Test
	public void issuerWhenOidcFallbackResponseMissingJwksUriThenThrowsIllegalArgumentException() throws Exception {
		this.response.remove("jwks_uri");
		assertThatThrownBy(() -> registrationOidcFallback("issuer1", null).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("The public JWK set URI must not be null");
	}

	// gh-7512
	@Test
	public void issuerWhenOAuth2ResponseMissingJwksUriThenThenSuccess() throws Exception {
		this.response.remove("jwks_uri");
		ClientRegistration registration = registrationOAuth2("", null).build();
		ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
		assertThat(provider.getJwkSetUri()).isNull();
	}

	// gh-8187
	@Test
	public void issuerWhenResponseMissingUserInfoUriThenSuccess() throws Exception {
		this.response.remove("userinfo_endpoint");
		ClientRegistration registration = registration("").build();
		assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri()).isNull();
	}

	@Test
	public void issuerWhenContainsTrailingSlashThenSuccess() throws Exception {
		assertThat(registration("")).isNotNull();
		assertThat(this.issuer).endsWith("/");
	}

	@Test
	public void issuerWhenOidcFallbackContainsTrailingSlashThenSuccess() throws Exception {
		assertThat(registrationOidcFallback("", null)).isNotNull();
		assertThat(this.issuer).endsWith("/");
	}

	@Test
	public void issuerWhenOAuth2ContainsTrailingSlashThenSuccess() throws Exception {
		assertThat(registrationOAuth2("", null)).isNotNull();
		assertThat(this.issuer).endsWith("/");
	}

	@Test
	public void issuerWhenGrantTypesSupportedNullThenDefaulted() throws Exception {
		this.response.remove("grant_types_supported");

		ClientRegistration registration = registration("").build();

		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	@Test
	public void issuerWhenOAuth2GrantTypesSupportedNullThenDefaulted() throws Exception {
		this.response.remove("grant_types_supported");

		ClientRegistration registration = registrationOAuth2("", null).build();

		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	/**
	 * We currently only support authorization_code, so verify we have a meaningful error until we add support.
	 */
	@Test
	public void issuerWhenGrantTypesSupportedInvalidThenException() {
		this.response.put("grant_types_supported", Arrays.asList("implicit"));

		assertThatThrownBy(() -> registration(""))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Only AuthorizationGrantType.AUTHORIZATION_CODE is supported. The issuer \"" + this.issuer + "\" returned a configuration of [implicit]");
	}

	@Test
	public void issuerWhenOAuth2GrantTypesSupportedInvalidThenException() {
		this.response.put("grant_types_supported", Arrays.asList("implicit"));

		assertThatThrownBy(() -> registrationOAuth2("", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Only AuthorizationGrantType.AUTHORIZATION_CODE is supported. The issuer \"" + this.issuer + "\" returned a configuration of [implicit]");
	}

	@Test
	public void issuerWhenTokenEndpointAuthMethodsNullThenDefaulted() throws Exception {
		this.response.remove("token_endpoint_auth_methods_supported");

		ClientRegistration registration = registration("").build();

		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
	}

	@Test
	public void issuerWhenOAuth2TokenEndpointAuthMethodsNullThenDefaulted() throws Exception {
		this.response.remove("token_endpoint_auth_methods_supported");

		ClientRegistration registration = registrationOAuth2("", null).build();

		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
	}

	@Test
	public void issuerWhenTokenEndpointAuthMethodsPostThenMethodIsPost() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_post"));

		ClientRegistration registration = registration("").build();

		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.POST);
	}

	@Test
	public void issuerWhenOAuth2TokenEndpointAuthMethodsPostThenMethodIsPost() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_post"));

		ClientRegistration registration = registrationOAuth2("", null).build();

		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.POST);
	}

	@Test
	public void issuerWhenTokenEndpointAuthMethodsNoneThenMethodIsNone() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("none"));

		ClientRegistration registration = registration("").build();

		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
	}

	@Test
	public void issuerWhenOAuth2TokenEndpointAuthMethodsNoneThenMethodIsNone() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("none"));

		ClientRegistration registration = registrationOAuth2("", null).build();

		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
	}

	/**
	 * We currently only support client_secret_basic, so verify we have a meaningful error until we add support.
	 */
	@Test
	public void issuerWhenTokenEndpointAuthMethodsInvalidThenException() {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("tls_client_auth"));

		assertThatThrownBy(() -> registration(""))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Only ClientAuthenticationMethod.BASIC, ClientAuthenticationMethod.POST and ClientAuthenticationMethod.NONE are supported. The issuer \"" + this.issuer + "\" returned a configuration of [tls_client_auth]");
	}

	@Test
	public void issuerWhenOAuth2TokenEndpointAuthMethodsInvalidThenException() {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("tls_client_auth"));

		assertThatThrownBy(() -> registrationOAuth2("", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Only ClientAuthenticationMethod.BASIC, ClientAuthenticationMethod.POST and ClientAuthenticationMethod.NONE are supported. The issuer \"" + this.issuer + "\" returned a configuration of [tls_client_auth]");
	}

	@Test
	public void issuerWhenOAuth2EmptyStringThenMeaningfulErrorMessage() {
		assertThatThrownBy(() -> ClientRegistrations.fromIssuerLocation(""))
				.hasMessageContaining("issuer cannot be empty");
	}

	@Test
	public void issuerWhenEmptyStringThenMeaningfulErrorMessage() {
		assertThatThrownBy(() -> ClientRegistrations.fromOidcIssuerLocation(""))
				.hasMessageContaining("issuer cannot be empty");
	}

	@Test
	public void issuerWhenOpenIdConfigurationDoesNotMatchThenMeaningfulErrorMessage()  throws Exception {
		this.issuer = createIssuerFromServer("");
		String body = this.mapper.writeValueAsString(this.response);
		MockResponse mockResponse = new MockResponse()
				.setBody(body)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(mockResponse);
		assertThatThrownBy(() -> ClientRegistrations.fromOidcIssuerLocation(this.issuer))
				.hasMessageContaining("The Issuer \"https://example.com\" provided in the configuration metadata did not match the requested issuer \"" + this.issuer + "\"");
	}

	@Test
	public void issuerWhenOAuth2ConfigurationDoesNotMatchThenMeaningfulErrorMessage()  throws Exception {
		this.issuer = createIssuerFromServer("");
		String body = this.mapper.writeValueAsString(this.response);
		MockResponse mockResponse = new MockResponse()
				.setBody(body)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(mockResponse);
		assertThatThrownBy(() -> ClientRegistrations.fromIssuerLocation(this.issuer))
				.hasMessageContaining("The Issuer \"https://example.com\" provided in the configuration metadata did not match the requested issuer \"" + this.issuer + "\"");
	}

	private ClientRegistration.Builder registration(String path) throws Exception {
		this.issuer = createIssuerFromServer(path);
		this.response.put("issuer", this.issuer);
		String body = this.mapper.writeValueAsString(this.response);
		MockResponse mockResponse = new MockResponse()
				.setBody(body)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(mockResponse);

		return ClientRegistrations.fromOidcIssuerLocation(this.issuer)
			.clientId("client-id")
			.clientSecret("client-secret");
	}

	private ClientRegistration.Builder registrationOAuth2(String path, String body) throws Exception {
		this.issuer = createIssuerFromServer(path);
		this.response.put("issuer", this.issuer);
		this.issuer = this.server.url(path).toString();
		final String responseBody = body != null ? body : this.mapper.writeValueAsString(this.response);

		final Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				switch(request.getPath()) {
					case "/.well-known/oauth-authorization-server/issuer1":
					case "/.well-known/oauth-authorization-server/":
						return buildSuccessMockResponse(responseBody);
				}
				return new MockResponse().setResponseCode(404);
			}
		};

		this.server.setDispatcher(dispatcher);

		return ClientRegistrations.fromIssuerLocation(this.issuer)
				.clientId("client-id")
				.clientSecret("client-secret");
	}


	private String createIssuerFromServer(String path) {
		return this.server.url(path).toString();
	}

	/**
	 * Simulates a situation when the ClientRegistration is used with a legacy application where the OIDC
	 * Discovery Endpoint is "/issuer1/.well-known/openid-configuration" instead of
	 * "/.well-known/openid-configuration/issuer1" in which case the first attempt results in HTTP 404 and
	 * the subsequent call results in 200 OK.
	 *
	 * @see <a href="https://tools.ietf.org/html/rfc8414#section-5">Section 5</a> for more details.
	 */
	private ClientRegistration.Builder registrationOidcFallback(String path, String body) throws Exception {
		this.issuer = createIssuerFromServer(path);
		this.response.put("issuer", this.issuer);

		String responseBody = body != null ? body : this.mapper.writeValueAsString(this.response);

		final Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				switch(request.getPath()) {
					case "/issuer1/.well-known/openid-configuration":
					case "/.well-known/openid-configuration/":
						return buildSuccessMockResponse(responseBody);
				}
				return new MockResponse().setResponseCode(404);
			}
		};
		this.server.setDispatcher(dispatcher);

		return ClientRegistrations.fromIssuerLocation(this.issuer)
				.clientId("client-id")
				.clientSecret("client-secret");
	}

	private MockResponse buildSuccessMockResponse(String body) {
		return new MockResponse().setResponseCode(200)
				.setBody(body)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
	}
}
