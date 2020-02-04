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
package org.springframework.security.config.oauth2.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * Tests for {@link ClientRegistrationsBeanDefinitionParser}.
 *
 * @author Ruby Hartono
 */
public class ClientRegistrationsBeanDefinitionParserTests {
	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/oauth2/client/ClientRegistrationsBeanDefinitionParserTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

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
			+ "    \"issuer\": \"http://localhost:49259\", \n"
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

	@Test
	public void parseWhenIssuerUriConfiguredThenRequestConfigFromIssuer() throws Exception {
		MockWebServer server = new MockWebServer();
		ObjectMapper mapper = new ObjectMapper();
		server.start(49259);
		Map<String, Object> response = mapper.readValue(DEFAULT_RESPONSE, new TypeReference<Map<String, Object>>() {
		});
		final String responseBody = mapper.writeValueAsString(response);

		final Dispatcher oidcDispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				switch (request.getPath()) {
				case "/issuer1/.well-known/openid-configuration":
				case "/.well-known/openid-configuration":
					return new MockResponse().setResponseCode(200).setBody(responseBody)
							.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
				}
				return new MockResponse().setResponseCode(404);
			}
		};

		final Dispatcher oauthDispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				switch (request.getPath()) {
				case "/.well-known/oauth-authorization-server/issuer1":
				case "/.well-known/oauth-authorization-server":
					return new MockResponse().setResponseCode(200).setBody(responseBody)
							.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
				}
				return new MockResponse().setResponseCode(404);
			}
		};

		server.setDispatcher(oidcDispatcher);

		this.spring.configLocations(this.xml("FromIssuerUri")).autowire();

		assertThat(clientRegistrationRepository).isInstanceOf(InMemoryClientRegistrationRepository.class);

		testIssuerUriResponse(clientRegistrationRepository);

		// test oauth
		server.setDispatcher(oauthDispatcher);
		this.spring.configLocations(this.xml("FromIssuerUri")).autowire();
		testIssuerUriResponse(clientRegistrationRepository);

		server.shutdown();
		server.close();
	}

	private void testIssuerUriResponse(ClientRegistrationRepository clientRegistrationRepository) {
		ClientRegistration googleLogin = clientRegistrationRepository.findByRegistrationId("google-login");
		assertThat(googleLogin).isNotNull();
		assertThat(googleLogin.getRegistrationId()).isEqualTo("google-login");
		assertThat(googleLogin.getClientId()).isEqualTo("google-client-id");
		assertThat(googleLogin.getClientSecret()).isEqualTo("google-client-secret");
		assertThat(googleLogin.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(googleLogin.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(googleLogin.getRedirectUriTemplate()).isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
		assertThat(googleLogin.getScopes()).isEqualTo(StringUtils.commaDelimitedListToSet("openid,profile,email"));
		assertThat(googleLogin.getClientName()).isEqualTo("Google");

		ProviderDetails googleProviderDetails = googleLogin.getProviderDetails();
		assertThat(googleProviderDetails).isNotNull();
		assertThat(googleProviderDetails.getAuthorizationUri()).isEqualTo("https://example.com/o/oauth2/v2/auth");
		assertThat(googleProviderDetails.getTokenUri()).isEqualTo("https://example.com/oauth2/v4/token");
		assertThat(googleProviderDetails.getUserInfoEndpoint().getUri())
				.isEqualTo("https://example.com/oauth2/v3/userinfo");
		assertThat(googleProviderDetails.getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.HEADER);
		assertThat(googleProviderDetails.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("sub");
		assertThat(googleProviderDetails.getJwkSetUri()).isEqualTo("https://example.com/oauth2/v3/certs");
	}

	@Test
	public void parseWhenMultipleClientsConfiguredThenAvailableInRepository() throws Exception {
		this.spring.configLocations(this.xml("MultiClientRegistration")).autowire();

		assertThat(clientRegistrationRepository).isInstanceOf(InMemoryClientRegistrationRepository.class);

		ClientRegistration googleLogin = clientRegistrationRepository.findByRegistrationId("google-login");
		assertThat(googleLogin).isNotNull();
		assertThat(googleLogin.getRegistrationId()).isEqualTo("google-login");
		assertThat(googleLogin.getClientId()).isEqualTo("google-client-id");
		assertThat(googleLogin.getClientSecret()).isEqualTo("google-client-secret");
		assertThat(googleLogin.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(googleLogin.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(googleLogin.getRedirectUriTemplate()).isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
		assertThat(googleLogin.getScopes()).isEqualTo(StringUtils.commaDelimitedListToSet("openid,profile,email"));
		assertThat(googleLogin.getClientName()).isEqualTo("Google");

		ProviderDetails googleProviderDetails = googleLogin.getProviderDetails();
		assertThat(googleProviderDetails).isNotNull();
		assertThat(googleProviderDetails.getAuthorizationUri())
				.isEqualTo("https://accounts.google.com/o/oauth2/v2/auth");
		assertThat(googleProviderDetails.getTokenUri()).isEqualTo("https://www.googleapis.com/oauth2/v4/token");
		assertThat(googleProviderDetails.getUserInfoEndpoint().getUri())
				.isEqualTo("https://www.googleapis.com/oauth2/v3/userinfo");
		assertThat(googleProviderDetails.getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.HEADER);
		assertThat(googleProviderDetails.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("sub");
		assertThat(googleProviderDetails.getJwkSetUri()).isEqualTo("https://www.googleapis.com/oauth2/v3/certs");

		ClientRegistration githubLogin = clientRegistrationRepository.findByRegistrationId("github-login");
		assertThat(githubLogin).isNotNull();
		assertThat(githubLogin.getRegistrationId()).isEqualTo("github-login");
		assertThat(githubLogin.getClientId()).isEqualTo("github-client-id");
		assertThat(githubLogin.getClientSecret()).isEqualTo("github-client-secret");
		assertThat(githubLogin.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(githubLogin.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(githubLogin.getRedirectUriTemplate()).isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
		assertThat(googleLogin.getScopes()).isEqualTo(StringUtils.commaDelimitedListToSet("openid,profile,email"));
		assertThat(githubLogin.getClientName()).isEqualTo("Github");

		ProviderDetails githubProviderDetails = githubLogin.getProviderDetails();
		assertThat(githubProviderDetails).isNotNull();
		assertThat(githubProviderDetails.getAuthorizationUri()).isEqualTo("https://github.com/login/oauth/authorize");
		assertThat(githubProviderDetails.getTokenUri()).isEqualTo("https://github.com/login/oauth/access_token");
		assertThat(githubProviderDetails.getUserInfoEndpoint().getUri()).isEqualTo("https://api.github.com/user");
		assertThat(githubProviderDetails.getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.HEADER);
		assertThat(githubProviderDetails.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("id");
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
