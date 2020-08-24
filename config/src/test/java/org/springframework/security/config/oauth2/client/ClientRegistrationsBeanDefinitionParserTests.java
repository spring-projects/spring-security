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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ClientRegistrationsBeanDefinitionParser}.
 *
 * @author Ruby Hartono
 */
public class ClientRegistrationsBeanDefinitionParserTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/oauth2/client/ClientRegistrationsBeanDefinitionParserTests";

	// @formatter:off
	private static final String ISSUER_URI_XML_CONFIG = "<b:beans xmlns:b=\"http://www.springframework.org/schema/beans\"\n"
			+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
			+ "		xmlns=\"http://www.springframework.org/schema/security\"\n"
			+ "		xsi:schemaLocation=\"\n"
			+ "			http://www.springframework.org/schema/security\n"
			+ "			https://www.springframework.org/schema/security/spring-security.xsd\n"
			+ "			http://www.springframework.org/schema/beans\n"
			+ "			https://www.springframework.org/schema/beans/spring-beans.xsd\">\n"
			+ "\n"
			+ "	<client-registrations>\n"
			+ "		<client-registration registration-id=\"google-login\" client-id=\"google-client-id\" \n"
			+ "							 client-secret=\"google-client-secret\" provider-id=\"google\"/>\n"
			+ "		<provider provider-id=\"google\" issuer-uri=\"${issuer-uri}\"/>\n"
			+ "	</client-registrations>\n"
			+ "\n"
			+ "</b:beans>\n";
	// @formatter:on

	// @formatter:off
	private static final String OIDC_DISCOVERY_RESPONSE = "{\n"
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
			+ "    \"issuer\": \"${issuer-uri}\", \n"
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

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	private MockWebServer server;

	@After
	public void cleanup() throws Exception {
		if (this.server != null) {
			this.server.shutdown();
		}
	}

	@Test
	public void parseWhenIssuerUriConfiguredThenRequestConfigFromIssuer() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String serverUrl = this.server.url("/").toString();
		String discoveryResponse = OIDC_DISCOVERY_RESPONSE.replace("${issuer-uri}", serverUrl);
		this.server.enqueue(jsonResponse(discoveryResponse));
		String contextConfig = ISSUER_URI_XML_CONFIG.replace("${issuer-uri}", serverUrl);
		this.spring.context(contextConfig).autowire();
		assertThat(this.clientRegistrationRepository).isInstanceOf(InMemoryClientRegistrationRepository.class);
		ClientRegistration googleRegistration = this.clientRegistrationRepository.findByRegistrationId("google-login");
		assertThat(googleRegistration).isNotNull();
		assertThat(googleRegistration.getRegistrationId()).isEqualTo("google-login");
		assertThat(googleRegistration.getClientId()).isEqualTo("google-client-id");
		assertThat(googleRegistration.getClientSecret()).isEqualTo("google-client-secret");
		assertThat(googleRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(googleRegistration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(googleRegistration.getRedirectUri()).isEqualTo("{baseUrl}/{action}/oauth2/code/{registrationId}");
		assertThat(googleRegistration.getScopes()).isNull();
		assertThat(googleRegistration.getClientName()).isEqualTo(serverUrl);
		ProviderDetails googleProviderDetails = googleRegistration.getProviderDetails();
		assertThat(googleProviderDetails).isNotNull();
		assertThat(googleProviderDetails.getAuthorizationUri()).isEqualTo("https://example.com/o/oauth2/v2/auth");
		assertThat(googleProviderDetails.getTokenUri()).isEqualTo("https://example.com/oauth2/v4/token");
		assertThat(googleProviderDetails.getUserInfoEndpoint().getUri())
				.isEqualTo("https://example.com/oauth2/v3/userinfo");
		assertThat(googleProviderDetails.getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.HEADER);
		assertThat(googleProviderDetails.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("sub");
		assertThat(googleProviderDetails.getJwkSetUri()).isEqualTo("https://example.com/oauth2/v3/certs");
		assertThat(googleProviderDetails.getIssuerUri()).isEqualTo(serverUrl);
	}

	@Test
	public void parseWhenMultipleClientsConfiguredThenAvailableInRepository() {
		this.spring.configLocations(ClientRegistrationsBeanDefinitionParserTests.xml("MultiClientRegistration"))
				.autowire();
		assertThat(this.clientRegistrationRepository).isInstanceOf(InMemoryClientRegistrationRepository.class);
		ClientRegistration googleRegistration = this.clientRegistrationRepository.findByRegistrationId("google-login");
		assertThat(googleRegistration).isNotNull();
		assertThat(googleRegistration.getRegistrationId()).isEqualTo("google-login");
		assertThat(googleRegistration.getClientId()).isEqualTo("google-client-id");
		assertThat(googleRegistration.getClientSecret()).isEqualTo("google-client-secret");
		assertThat(googleRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(googleRegistration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(googleRegistration.getRedirectUri()).isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
		assertThat(googleRegistration.getScopes())
				.isEqualTo(StringUtils.commaDelimitedListToSet("openid,profile,email"));
		assertThat(googleRegistration.getClientName()).isEqualTo("Google");
		ProviderDetails googleProviderDetails = googleRegistration.getProviderDetails();
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
		assertThat(googleProviderDetails.getIssuerUri()).isEqualTo("https://accounts.google.com");
		ClientRegistration githubRegistration = this.clientRegistrationRepository.findByRegistrationId("github-login");
		assertThat(githubRegistration).isNotNull();
		assertThat(githubRegistration.getRegistrationId()).isEqualTo("github-login");
		assertThat(githubRegistration.getClientId()).isEqualTo("github-client-id");
		assertThat(githubRegistration.getClientSecret()).isEqualTo("github-client-secret");
		assertThat(githubRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(githubRegistration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(githubRegistration.getRedirectUri()).isEqualTo("{baseUrl}/login/oauth2/code/{registrationId}");
		assertThat(googleRegistration.getScopes())
				.isEqualTo(StringUtils.commaDelimitedListToSet("openid,profile,email"));
		assertThat(githubRegistration.getClientName()).isEqualTo("Github");
		ProviderDetails githubProviderDetails = githubRegistration.getProviderDetails();
		assertThat(githubProviderDetails).isNotNull();
		assertThat(githubProviderDetails.getAuthorizationUri()).isEqualTo("https://github.com/login/oauth/authorize");
		assertThat(githubProviderDetails.getTokenUri()).isEqualTo("https://github.com/login/oauth/access_token");
		assertThat(githubProviderDetails.getUserInfoEndpoint().getUri()).isEqualTo("https://api.github.com/user");
		assertThat(githubProviderDetails.getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.HEADER);
		assertThat(githubProviderDetails.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("id");
	}

	private static MockResponse jsonResponse(String json) {
		return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json);
	}

	private static String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
