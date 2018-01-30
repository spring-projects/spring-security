/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link AuthorizationCodeGrantConfigurer}.
 *
 * @author Joe Grandja
 */
@PrepareForTest({OAuth2AuthorizationRequest.class, OAuth2AccessTokenResponse.class})
@RunWith(PowerMockRunner.class)
public class AuthorizationCodeGrantConfigurerTests {
	private static ClientRegistrationRepository clientRegistrationRepository;

	private static OAuth2AuthorizedClientService authorizedClientService;

	private static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	private ClientRegistration registration1;

	@Before
	public void setup() {
		this.registration1 = ClientRegistration.withRegistrationId("registration-1")
			.clientId("client-1")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate("{baseUrl}/client-1")
			.scope("user")
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.userInfoUri("https://provider.com/oauth2/user")
			.userNameAttributeName("id")
			.clientName("client-1")
			.build();
		clientRegistrationRepository = new InMemoryClientRegistrationRepository(this.registration1);

		authorizedClientService = new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);

		OAuth2AccessTokenResponse accessTokenResponse = mock(OAuth2AccessTokenResponse.class);
		when(accessTokenResponse.getAccessToken()).thenReturn(mock(OAuth2AccessToken.class));
		accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		when(accessTokenResponseClient.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class))).thenReturn(accessTokenResponse);
	}

	@Test
	public void configureWhenAuthorizationRequestThenRedirectForAuthorization() throws Exception {
		this.spring.register(AuthorizationCodeGrantConfig.class).autowire();

		MvcResult mvcResult = this.mockMvc.perform(get("/oauth2/authorization/registration-1"))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).matches("https://provider.com/oauth2/authorize\\?response_type=code&client_id=client-1&scope=user&state=.{15,}&redirect_uri=http://localhost/client-1");
	}

	@Test
	public void configureWhenAuthorizationResponseSuccessThenAuthorizedClientSaved() throws Exception {
		this.spring.register(AuthorizationCodeGrantConfig.class).autowire();

		// Setup the Authorization Request in the session
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, this.registration1.getRegistrationId());
		OAuth2AuthorizationRequest authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest.getAdditionalParameters()).thenReturn(additionalParameters);
		when(authorizationRequest.getState()).thenReturn("state");
		when(authorizationRequest.getRedirectUri()).thenReturn("http://localhost/client-1");
		MockHttpSession session = new MockHttpSession();
		session.setAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST", authorizationRequest);

		String principalName = "user1";

		this.mockMvc.perform(get("/client-1")
			.param(OAuth2ParameterNames.CODE, "code")
			.param(OAuth2ParameterNames.STATE, "state")
			.with(user(principalName))
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost/client-1"));

		OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
			this.registration1.getRegistrationId(), principalName);
		assertThat(authorizedClient).isNotNull();
	}

	@EnableWebSecurity
	static class AuthorizationCodeGrantConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated();

			this.authorizationCodeGrant(http)
				.clientRegistrationRepository(clientRegistrationRepository)
				.authorizedClientService(authorizedClientService)
				.tokenEndpoint()
					.accessTokenResponseClient(accessTokenResponseClient);
		}

		private AuthorizationCodeGrantConfigurer<HttpSecurity> authorizationCodeGrant(HttpSecurity http) throws Exception {
			return http.apply(new AuthorizationCodeGrantConfigurer<>());
		}
	}
}
