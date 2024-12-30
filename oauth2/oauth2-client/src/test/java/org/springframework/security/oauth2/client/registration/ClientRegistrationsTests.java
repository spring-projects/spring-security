/*
 * Copyright 2002-2021 the original author or authors.
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

import java.net.URI;
import java.util.Arrays;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * @author Rob Winch
 * @author Rafiullah Hamedy
 * @since 5.1
 */
public class ClientRegistrationsTests {

	/**
	 * Contains all optional parameters that are found in ClientRegistration
	 */
	// @formatter:off
	private static final String DEFAULT_RESPONSE = "{\n"
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
	// @formatter:on

	private MockWebServer server;

	private ObjectMapper mapper = new ObjectMapper();

	private Map<String, Object> response;

	private String issuer;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.response = this.mapper.readValue(DEFAULT_RESPONSE, new TypeReference<Map<String, Object>>() {
		});
	}

	@AfterEach
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
	 * Test compatibility with OpenID v1 discovery endpoint by making a <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID
	 * Provider Configuration Request</a> as highlighted
	 * <a href="https://tools.ietf.org/html/rfc8414#section-5"> Compatibility Notes</a> of
	 * <a href="https://tools.ietf.org/html/rfc8414">RFC 8414</a> specification.
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

	private void assertIssuerMetadata(ClientRegistration registration, ClientRegistration.ProviderDetails provider) {
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registration.getRegistrationId()).isEqualTo(URI.create(this.issuer).getHost());
		assertThat(registration.getClientName()).isEqualTo(this.issuer);
		assertThat(registration.getScopes()).isNull();
		assertThat(provider.getAuthorizationUri()).isEqualTo("https://example.com/o/oauth2/v2/auth");
		assertThat(provider.getTokenUri()).isEqualTo("https://example.com/oauth2/v4/token");
		assertThat(provider.getJwkSetUri()).isEqualTo("https://example.com/oauth2/v3/certs");
		assertThat(provider.getIssuerUri()).isEqualTo(this.issuer);
		assertThat(provider.getConfigurationMetadata()).containsKeys("authorization_endpoint", "claims_supported",
				"code_challenge_methods_supported", "id_token_signing_alg_values_supported", "issuer", "jwks_uri",
				"response_types_supported", "revocation_endpoint", "scopes_supported", "subject_types_supported",
				"grant_types_supported", "token_endpoint", "token_endpoint_auth_methods_supported",
				"userinfo_endpoint");
	}

	// gh-7512
	@Test
	public void issuerWhenResponseMissingJwksUriThenThrowsIllegalArgumentException() throws Exception {
		this.response.remove("jwks_uri");
		assertThatIllegalArgumentException().isThrownBy(() -> registration("").build())
			.withMessageContaining("The public JWK set URI must not be null");
	}

	// gh-7512
	@Test
	public void issuerWhenOidcFallbackResponseMissingJwksUriThenThrowsIllegalArgumentException() throws Exception {
		this.response.remove("jwks_uri");
		assertThatIllegalArgumentException().isThrownBy(() -> registrationOidcFallback("issuer1", null).build())
			.withMessageContaining("The public JWK set URI must not be null");
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

	// gh-9828
	@Test
	public void issuerWhenImplicitGrantTypeThenSuccess() throws Exception {
		this.response.put("grant_types_supported", Arrays.asList("implicit"));
		ClientRegistration registration = registration("").build();
		// The authorization_code grant type is still the default
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	// gh-9828
	@Test
	public void issuerWhenOAuth2JwtBearerGrantTypeThenSuccess() throws Exception {
		this.response.put("grant_types_supported", Arrays.asList("urn:ietf:params:oauth:grant-type:jwt-bearer"));
		ClientRegistration registration = registrationOAuth2("", null).build();
		// The authorization_code grant type is still the default
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	// gh-9795
	@Test
	public void issuerWhenResponseAuthorizationEndpointIsNullThenSuccess() throws Exception {
		this.response.put("grant_types_supported", Arrays.asList("urn:ietf:params:oauth:grant-type:jwt-bearer"));
		this.response.remove("authorization_endpoint");
		ClientRegistration registration = registration("").authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
			.build();
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.JWT_BEARER);
		ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
		assertThat(provider.getAuthorizationUri()).isNull();
	}

	// gh-9795
	@Test
	public void issuerWhenOAuth2ResponseAuthorizationEndpointIsNullThenSuccess() throws Exception {
		this.response.put("grant_types_supported", Arrays.asList("urn:ietf:params:oauth:grant-type:jwt-bearer"));
		this.response.remove("authorization_endpoint");
		ClientRegistration registration = registrationOAuth2("", null)
			.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
			.build();
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.JWT_BEARER);
		ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
		assertThat(provider.getAuthorizationUri()).isNull();
	}

	@Test
	public void issuerWhenTokenEndpointAuthMethodsNullThenDefaulted() throws Exception {
		this.response.remove("token_endpoint_auth_methods_supported");
		ClientRegistration registration = registration("").build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void issuerWhenOAuth2TokenEndpointAuthMethodsNullThenDefaulted() throws Exception {
		this.response.remove("token_endpoint_auth_methods_supported");
		ClientRegistration registration = registrationOAuth2("", null).build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	// gh-9780
	@Test
	public void issuerWhenClientSecretBasicAuthMethodThenMethodIsBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_basic"));
		ClientRegistration registration = registration("").build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	// gh-9780
	@Test
	public void issuerWhenOAuth2ClientSecretBasicAuthMethodThenMethodIsBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_basic"));
		ClientRegistration registration = registrationOAuth2("", null).build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void issuerWhenTokenEndpointAuthMethodsPostThenMethodIsPost() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_post"));
		ClientRegistration registration = registration("").build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
	}

	@Test
	public void issuerWhenOAuth2TokenEndpointAuthMethodsPostThenMethodIsPost() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_post"));
		ClientRegistration registration = registrationOAuth2("", null).build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
	}

	// gh-9780
	@Test
	public void issuerWhenClientSecretJwtAuthMethodThenMethodIsClientSecretBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_jwt"));
		ClientRegistration registration = registration("").build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	// gh-9780
	@Test
	public void issuerWhenOAuth2ClientSecretJwtAuthMethodThenMethodIsClientSecretBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_jwt"));
		ClientRegistration registration = registrationOAuth2("", null).build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	// gh-9780
	@Test
	public void issuerWhenPrivateKeyJwtAuthMethodThenMethodIsClientSecretBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("private_key_jwt"));
		ClientRegistration registration = registration("").build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	// gh-9780
	@Test
	public void issuerWhenOAuth2PrivateKeyJwtAuthMethodThenMethodIsClientSecretBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("private_key_jwt"));
		ClientRegistration registration = registrationOAuth2("", null).build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
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

	// gh-9780
	@Test
	public void issuerWhenTlsClientAuthMethodThenSuccess() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("tls_client_auth"));
		ClientRegistration registration = registration("").build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	// gh-9780
	@Test
	public void issuerWhenOAuth2TlsClientAuthMethodThenSuccess() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("tls_client_auth"));
		ClientRegistration registration = registrationOAuth2("", null).build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void issuerWhenOAuth2EmptyStringThenMeaningfulErrorMessage() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ClientRegistrations.fromIssuerLocation(""))
				.withMessageContaining("issuer cannot be empty");
		// @formatter:on
	}

	@Test
	public void issuerWhenEmptyStringThenMeaningfulErrorMessage() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ClientRegistrations.fromOidcIssuerLocation(""))
				.withMessageContaining("issuer cannot be empty");
		// @formatter:on
	}

	@Test
	public void issuerWhenOpenIdConfigurationDoesNotMatchThenMeaningfulErrorMessage() throws Exception {
		this.issuer = createIssuerFromServer("");
		String body = this.mapper.writeValueAsString(this.response);
		MockResponse mockResponse = new MockResponse().setBody(body)
			.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(mockResponse);
		// @formatter:off
		assertThatIllegalStateException()
				.isThrownBy(() -> ClientRegistrations.fromOidcIssuerLocation(this.issuer))
				.withMessageContaining("The Issuer \"https://example.com\" provided in the configuration metadata did "
						+ "not match the requested issuer \"" + this.issuer + "\"");
		// @formatter:on
	}

	@Test
	public void issuerWhenOAuth2ConfigurationDoesNotMatchThenMeaningfulErrorMessage() throws Exception {
		this.issuer = createIssuerFromServer("");
		String body = this.mapper.writeValueAsString(this.response);
		MockResponse mockResponse = new MockResponse().setBody(body)
			.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(mockResponse);
		// @formatter:off
		assertThatIllegalStateException()
				.isThrownBy(() -> ClientRegistrations.fromIssuerLocation(this.issuer))
				.withMessageContaining("The Issuer \"https://example.com\" provided in the configuration metadata "
						+ "did not match the requested issuer \"" + this.issuer + "\"");
		// @formatter:on
	}

	@Test
	public void issuerWhenOidcConfigurationAllInformationThenSuccess() throws Exception {
		ClientRegistration registration = registration(this.response).build();
		ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
		assertIssuerMetadata(registration, provider);
		assertThat(provider.getUserInfoEndpoint().getUri()).isEqualTo("https://example.com/oauth2/v3/userinfo");
	}

	private ClientRegistration.Builder registration(Map<String, Object> configuration) {
		this.issuer = "https://example.com";
		return ClientRegistrations.fromOidcConfiguration(configuration)
			.clientId("client-id")
			.clientSecret("client-secret");
	}

	@Test
	public void issuerWhenOidcConfigurationResponseMissingJwksUriThenThrowsIllegalArgumentException() throws Exception {
		this.response.remove("jwks_uri");
		assertThatIllegalArgumentException().isThrownBy(() -> registration(this.response).build())
			.withMessageContaining("The public JWK set URI must not be null");
	}

	@Test
	public void issuerWhenOidcConfigurationResponseMissingUserInfoUriThenSuccess() throws Exception {
		this.response.remove("userinfo_endpoint");
		ClientRegistration registration = registration(this.response).build();
		assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri()).isNull();
	}

	@Test
	public void issuerWhenOidcConfigurationGrantTypesSupportedNullThenDefaulted() throws Exception {
		this.response.remove("grant_types_supported");
		ClientRegistration registration = registration(this.response).build();
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	@Test
	public void issuerWhenOidcConfigurationImplicitGrantTypeThenSuccess() throws Exception {
		this.response.put("grant_types_supported", Arrays.asList("implicit"));
		ClientRegistration registration = registration(this.response).build();
		// The authorization_code grant type is still the default
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	@Test
	public void issuerWhenOidcConfigurationResponseAuthorizationEndpointIsNullThenSuccess() throws Exception {
		this.response.put("grant_types_supported", Arrays.asList("urn:ietf:params:oauth:grant-type:jwt-bearer"));
		this.response.remove("authorization_endpoint");
		ClientRegistration registration = registration(this.response)
			.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
			.build();
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.JWT_BEARER);
		ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
		assertThat(provider.getAuthorizationUri()).isNull();
	}

	@Test
	public void issuerWhenOidcConfigurationTokenEndpointAuthMethodsNullThenDefaulted() throws Exception {
		this.response.remove("token_endpoint_auth_methods_supported");
		ClientRegistration registration = registration(this.response).build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void issuerWhenOidcConfigurationClientSecretBasicAuthMethodThenMethodIsBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_basic"));
		ClientRegistration registration = registration(this.response).build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void issuerWhenOidcConfigurationTokenEndpointAuthMethodsPostThenMethodIsPost() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_post"));
		ClientRegistration registration = registration(this.response).build();
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
	}

	@Test
	public void issuerWhenOidcConfigurationClientSecretJwtAuthMethodThenMethodIsClientSecretBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_jwt"));
		ClientRegistration registration = registration(this.response).build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void issuerWhenOidcConfigurationPrivateKeyJwtAuthMethodThenMethodIsClientSecretBasic() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("private_key_jwt"));
		ClientRegistration registration = registration(this.response).build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void issuerWhenOidcConfigurationTokenEndpointAuthMethodsNoneThenMethodIsNone() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("none"));
		ClientRegistration registration = registration(this.response).build();
		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
	}

	@Test
	public void issuerWhenOidcConfigurationTlsClientAuthMethodThenSuccess() throws Exception {
		this.response.put("token_endpoint_auth_methods_supported", Arrays.asList("tls_client_auth"));
		ClientRegistration registration = registration(this.response).build();
		// The client_secret_basic auth method is still the default
		assertThat(registration.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	private ClientRegistration.Builder registration(String path) throws Exception {
		this.issuer = createIssuerFromServer(path);
		this.response.put("issuer", this.issuer);
		String body = this.mapper.writeValueAsString(this.response);
		// @formatter:off
		MockResponse mockResponse = new MockResponse()
				.setBody(body)
				.setHeader(HttpHeaders.CONTENT_TYPE,
				MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(mockResponse);
		return ClientRegistrations.fromOidcIssuerLocation(this.issuer)
				.clientId("client-id")
				.clientSecret("client-secret");
		// @formatter:on
	}

	private ClientRegistration.Builder registrationOAuth2(String path, String body) throws Exception {
		this.issuer = createIssuerFromServer(path);
		this.response.put("issuer", this.issuer);
		this.issuer = this.server.url(path).toString();
		final String responseBody = (body != null) ? body : this.mapper.writeValueAsString(this.response);
		final Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				return switch (request.getPath()) {
					case "/.well-known/oauth-authorization-server/issuer1",
							"/.well-known/oauth-authorization-server/" ->
						buildSuccessMockResponse(responseBody);
					default -> new MockResponse().setResponseCode(404);
				};
			}
		};
		this.server.setDispatcher(dispatcher);
		// @formatter:off
		return ClientRegistrations.fromIssuerLocation(this.issuer)
				.clientId("client-id")
				.clientSecret("client-secret");
		// @formatter:on
	}

	private String createIssuerFromServer(String path) {
		return this.server.url(path).toString();
	}

	/**
	 * Simulates a situation when the ClientRegistration is used with a legacy application
	 * where the OIDC Discovery Endpoint is "/issuer1/.well-known/openid-configuration"
	 * instead of "/.well-known/openid-configuration/issuer1" in which case the first
	 * attempt results in HTTP 404 and the subsequent call results in 200 OK.
	 *
	 * @see <a href="https://tools.ietf.org/html/rfc8414#section-5">Section 5</a> for more
	 * details.
	 */
	private ClientRegistration.Builder registrationOidcFallback(String path, String body) throws Exception {
		this.issuer = createIssuerFromServer(path);
		this.response.put("issuer", this.issuer);
		String responseBody = (body != null) ? body : this.mapper.writeValueAsString(this.response);
		final Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				return switch (request.getPath()) {
					case "/issuer1/.well-known/openid-configuration", "/.well-known/openid-configuration/" ->
						buildSuccessMockResponse(responseBody);
					default -> new MockResponse().setResponseCode(404);
				};
			}
		};
		this.server.setDispatcher(dispatcher);
		return ClientRegistrations.fromIssuerLocation(this.issuer).clientId("client-id").clientSecret("client-secret");
	}

	private MockResponse buildSuccessMockResponse(String body) {
		// @formatter:off
		return new MockResponse().setResponseCode(200)
				.setBody(body)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		// @formatter:on
	}

}
