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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for OAuth2 Authorization Code Grant final redirect
 *
 * @author Tadaya Tsuyukubo
 * @see org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter
 */
public class OAuth2AuthorizationCodeGrantRedirectTests {

	private static AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
	private static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Before
	public void setUp() {
		authorizationRequestRepository = mock(AuthorizationRequestRepository.class);
		accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
	}

	@Test
	public void redirect() throws Exception {
		perform("/redirect?code=MY-CODE&state=MY-STATE",
				"http://localhost/redirect",
				"http://localhost/redirect");
	}

	@Test
	public void redirectWithParamAppended() throws Exception {
		perform("/redirect?code=MY-CODE&state=MY-STATE&extra=EXTRA",
				"http://localhost/redirect",
				"http://localhost/redirect?extra=EXTRA");
	}

	@Test
	public void redirectWithParameters() throws Exception {
		perform("/redirect?foo=FOO&code=MY-CODE&state=MY-STATE",
				"http://localhost/redirect?foo=FOO",
				"http://localhost/redirect?foo=FOO");
	}

	@Test
	public void redirectUrlWithParametersWithParamAppended() throws Exception {
		perform("/redirect?foo=FOO&code=MY-CODE&state=MY-STATE&extra=EXTRA",
				"http://localhost/redirect?foo=FOO",
				"http://localhost/redirect?foo=FOO&extra=EXTRA");
	}

	private void perform(String requestUri, String authorizationRequestRedirectUri, String expectedRedirectUrl) throws Exception {
		this.spring.register(WebSecurityConfiguration.class).autowire();

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest
				.authorizationCode()
				.authorizationUri("http://localhost/auth")
				.clientId("example")
				.state("MY-STATE")
				.redirectUri(authorizationRequestRedirectUri)
				.attributes(Collections.singletonMap(OAuth2ParameterNames.REGISTRATION_ID, "registration-id")) // comes from TestClientRegistrations.clientRegistration
				.build();

		when(authorizationRequestRepository.loadAuthorizationRequest(any(HttpServletRequest.class)))
				.thenReturn(authorizationRequest);
		when(authorizationRequestRepository.removeAuthorizationRequest(any(HttpServletRequest.class), any(HttpServletResponse.class)))
				.thenReturn(authorizationRequest);

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
				.withToken("MY-ACCESS-TOKEN")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.build();
		when(accessTokenResponseClient
				.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class)))
						.thenReturn(accessTokenResponse);

		MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(requestUri);
		this.mvc.perform(builder)
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl(expectedRedirectUrl));
	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {

			ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();

			InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository =
					new InMemoryClientRegistrationRepository(clientRegistration);

			http.oauth2Client(oauth2client ->
					oauth2client
							.clientRegistrationRepository(inMemoryClientRegistrationRepository)
							.authorizationCodeGrant()
							.authorizationRequestRepository(authorizationRequestRepository)
							.accessTokenResponseClient(accessTokenResponseClient)
			);
		}
	}

}
