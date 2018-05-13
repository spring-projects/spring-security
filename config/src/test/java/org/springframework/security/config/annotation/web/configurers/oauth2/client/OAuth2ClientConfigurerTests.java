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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.OAuth2Client;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link OAuth2ClientConfigurer}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientConfigurerTests {
	private static ClientRegistrationRepository clientRegistrationRepository;

	private static OAuth2AuthorizedClientService authorizedClientService;

	private static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private static RequestCache requestCache;

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
			.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}")
			.scope("user")
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.userInfoUri("https://provider.com/oauth2/user")
			.userNameAttributeName("id")
			.clientName("client-1")
			.build();
		clientRegistrationRepository = new InMemoryClientRegistrationRepository(this.registration1);
		authorizedClientService = new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("access-token-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(300)
				.build();
		accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		when(accessTokenResponseClient.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class))).thenReturn(accessTokenResponse);
		requestCache = mock(RequestCache.class);
	}

	@Test
	public void configureWhenAuthorizationCodeRequestThenRedirectForAuthorization() throws Exception {
		this.spring.register(OAuth2ClientConfig.class).autowire();

		MvcResult mvcResult = this.mockMvc.perform(get("/oauth2/authorization/registration-1"))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).matches("https://provider.com/oauth2/authorize\\?response_type=code&client_id=client-1&scope=user&state=.{15,}&redirect_uri=http://localhost/login/oauth2/code/registration-1");
	}

	@Test
	public void configureWhenAuthorizationCodeResponseSuccessThenAuthorizedClientSaved() throws Exception {
		this.spring.register(OAuth2ClientConfig.class).autowire();

		// Setup the Authorization Request in the session
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, this.registration1.getRegistrationId());
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(this.registration1.getProviderDetails().getAuthorizationUri())
				.clientId(this.registration1.getClientId())
				.redirectUri("http://localhost/authorize/oauth2/code/registration-1")
				.state("state")
				.additionalParameters(additionalParameters)
				.build();

		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
				new HttpSessionOAuth2AuthorizationRequestRepository();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response, this.registration1);

		MockHttpSession session = (MockHttpSession) request.getSession();

		String principalName = "user1";

		this.mockMvc.perform(get("/authorize/oauth2/code/registration-1")
			.param(OAuth2ParameterNames.CODE, "code")
			.param(OAuth2ParameterNames.STATE, "state")
			.with(user(principalName))
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost/authorize/oauth2/code/registration-1"));

		OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
			this.registration1.getRegistrationId(), principalName);
		assertThat(authorizedClient).isNotNull();
	}

	@Test
	public void configureWhenRequestCacheProvidedAndClientAuthorizationRequiredExceptionThrownThenRequestCacheUsed() throws Exception {
		this.spring.register(OAuth2ClientConfig.class).autowire();

		MvcResult mvcResult = this.mockMvc.perform(get("/resource1").with(user("user1")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).matches("https://provider.com/oauth2/authorize\\?response_type=code&client_id=client-1&scope=user&state=.{15,}&redirect_uri=http://localhost/authorize/oauth2/code/registration-1");

		verify(requestCache).saveRequest(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@EnableWebSecurity
	@EnableWebMvc
	static class OAuth2ClientConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.requestCache()
					.requestCache(requestCache)
					.and()
				.oauth2()
					.client()
						.authorizationCodeGrant()
							.tokenEndpoint()
								.accessTokenResponseClient(accessTokenResponseClient);
		}

		@Bean
		public ClientRegistrationRepository clientRegistrationRepository() {
			return clientRegistrationRepository;
		}

		@Bean
		public OAuth2AuthorizedClientService authorizedClientService() {
			return authorizedClientService;
		}

		@RestController
		public class ResourceController {
			@GetMapping("/resource1")
			public String resource1(@OAuth2Client("registration-1") OAuth2AuthorizedClient authorizedClient) {
				return "resource1";
			}
		}
	}
}
