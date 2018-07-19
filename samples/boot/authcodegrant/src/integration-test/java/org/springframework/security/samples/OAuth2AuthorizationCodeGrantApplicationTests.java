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
package org.springframework.security.samples;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import sample.config.WebClientConfig;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 client filters {@link OAuth2AuthorizationRequestRedirectFilter}
 * and {@link OAuth2AuthorizationCodeGrantFilter}. These filters work together to realize
 * the OAuth 2.0 Authorization Code Grant flow.
 *
 * @author Joe Grandja
 * @since 5.1
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class OAuth2AuthorizationCodeGrantApplicationTests {
	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void requestWhenClientNotAuthorizedThenRedirectForAuthorization() throws Exception {
		MvcResult mvcResult = this.mockMvc.perform(get("/repos").with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).matches("https://github.com/login/oauth/authorize\\?response_type=code&client_id=your-app-client-id&scope=public_repo&state=.{15,}&redirect_uri=http%3A%2F%2Flocalhost%2Fgithub-repos");
	}

	@Test
	@DirtiesContext
	public void requestWhenClientGrantedAuthorizationThenAuthorizedClientSaved() throws Exception {
		// Setup the Authorization Request in the session
		ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId("github");
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, registration.getRegistrationId());
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
			.clientId(registration.getClientId())
			.redirectUri("http://localhost/github-repos")
			.scopes(registration.getScopes())
			.state("state")
			.additionalParameters(additionalParameters)
			.build();

		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
				new HttpSessionOAuth2AuthorizationRequestRepository();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);

		MockHttpSession session = (MockHttpSession) request.getSession();

		String principalName = "user";
		TestingAuthenticationToken authentication = new TestingAuthenticationToken(principalName, "password");

		// Authorization Response
		this.mockMvc.perform(get("/github-repos")
			.param(OAuth2ParameterNames.CODE, "code")
			.param(OAuth2ParameterNames.STATE, "state")
			.with(authentication(authentication))
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost/github-repos"));

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
			registration.getRegistrationId(), authentication, request);
		assertThat(authorizedClient).isNotNull();
	}

	@EnableWebSecurity
	static class OAuth2ClientConfig extends WebSecurityConfigurerAdapter {
		// @formatter:off
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2()
					.client()
						.authorizationCodeGrant()
							.tokenEndpoint()
								.accessTokenResponseClient(this.accessTokenResponseClient());
		}
		// @formatter:on

		private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
			OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("access-token-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(60 * 1000)
				.build();
			OAuth2AccessTokenResponseClient tokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
			when(tokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);
			return tokenResponseClient;
		}
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample.web")
	@Import(WebClientConfig.class)
	public static class SpringBootApplicationTestConfig {

		@Bean
		public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
			return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
		}

		@Bean
		public OAuth2AuthorizedClientRepository authorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
			return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
		}
	}
}
