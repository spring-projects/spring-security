/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link OAuth2ClientConfigurer}.
 *
 * @author Joe Grandja
 * @author Parikshit Dutta
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2ClientConfigurerTests {

	private static ClientRegistrationRepository clientRegistrationRepository;

	private static OAuth2AuthorizedClientService authorizedClientService;

	private static OAuth2AuthorizedClientRepository authorizedClientRepository;

	private static OAuth2AuthorizationRequestResolver authorizationRequestResolver;

	private static RedirectStrategy authorizationRedirectStrategy;

	private static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private static RequestCache requestCache;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	private ClientRegistration registration1;

	@BeforeEach
	public void setup() {
		// @formatter:off
		this.registration1 = TestClientRegistrations.clientRegistration()
				.registrationId("registration-1")
				.clientId("client-1")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("{baseUrl}/client-1")
				.scope("user")
				.authorizationUri("https://provider.com/oauth2/authorize")
				.tokenUri("https://provider.com/oauth2/token")
				.userInfoUri("https://provider.com/oauth2/user")
				.userNameAttributeName("id")
				.clientName("client-1")
				.build();
		// @formatter:on
		clientRegistrationRepository = new InMemoryClientRegistrationRepository(this.registration1);
		authorizedClientService = new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
		authorizedClientRepository = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
				authorizedClientService);
		authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
				"/oauth2/authorization");
		authorizationRedirectStrategy = new DefaultRedirectStrategy();
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("access-token-1234")
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.expiresIn(300)
			.build();
		accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		given(accessTokenResponseClient.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class)))
			.willReturn(accessTokenResponse);
		requestCache = mock(RequestCache.class);
	}

	@Test
	public void configureWhenAuthorizationCodeRequestThenRedirectForAuthorization() throws Exception {
		this.spring.register(OAuth2ClientConfig.class).autowire();
		// @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(get("/oauth2/authorization/registration-1"))
				.andExpect(status().is3xxRedirection()).andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl())
				.matches("https://provider.com/oauth2/authorize\\?" + "response_type=code&client_id=client-1&"
						+ "scope=user&state=.{15,}&" + "redirect_uri=http://localhost/client-1");
		// @formatter:on
	}

	@Test
	public void configureWhenOauth2ClientInLambdaThenRedirectForAuthorization() throws Exception {
		this.spring.register(OAuth2ClientInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mockMvc.perform(get("/oauth2/authorization/registration-1"))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl())
			.matches("https://provider.com/oauth2/authorize\\?" + "response_type=code&client_id=client-1&"
					+ "scope=user&state=.{15,}&" + "redirect_uri=http://localhost/client-1");
	}

	@Test
	public void configureWhenAuthorizationCodeResponseSuccessThenAuthorizedClientSaved() throws Exception {
		this.spring.register(OAuth2ClientConfig.class).autowire();
		// Setup the Authorization Request in the session
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, this.registration1.getRegistrationId());
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(this.registration1.getProviderDetails().getAuthorizationUri())
				.clientId(this.registration1.getClientId())
				.redirectUri("http://localhost/client-1")
				.state("state")
				.attributes(attributes)
				.build();
		// @formatter:on
		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
		MockHttpSession session = (MockHttpSession) request.getSession();
		String principalName = "user1";
		TestingAuthenticationToken authentication = new TestingAuthenticationToken(principalName, "password");
		// @formatter:off
		MockHttpServletRequestBuilder clientRequest = get("/client-1")
				.param(OAuth2ParameterNames.CODE, "code")
				.param(OAuth2ParameterNames.STATE, "state")
				.with(authentication(authentication))
				.session(session);
		this.mockMvc.perform(clientRequest)
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/client-1"));
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = authorizedClientRepository
			.loadAuthorizedClient(this.registration1.getRegistrationId(), authentication, request);
		assertThat(authorizedClient).isNotNull();
	}

	@Test
	public void configureWhenRequestCacheProvidedAndClientAuthorizationRequiredExceptionThrownThenRequestCacheUsed()
			throws Exception {
		this.spring.register(OAuth2ClientConfig.class).autowire();
		MvcResult mvcResult = this.mockMvc.perform(get("/resource1").with(user("user1")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl())
			.matches("https://provider.com/oauth2/authorize\\?" + "response_type=code&client_id=client-1&"
					+ "scope=user&state=.{15,}&" + "redirect_uri=http://localhost/client-1");
		verify(requestCache).saveRequest(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void configureWhenRequestCacheProvidedAndClientAuthorizationSucceedsThenRequestCacheUsed() throws Exception {
		this.spring.register(OAuth2ClientConfig.class).autowire();
		// Setup the Authorization Request in the session
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, this.registration1.getRegistrationId());
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(this.registration1.getProviderDetails().getAuthorizationUri())
				.clientId(this.registration1.getClientId()).redirectUri("http://localhost/client-1")
				.state("state")
				.attributes(attributes)
				.build();
		// @formatter:on
		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
		MockHttpSession session = (MockHttpSession) request.getSession();
		String principalName = "user1";
		TestingAuthenticationToken authentication = new TestingAuthenticationToken(principalName, "password");
		// @formatter:off
		MockHttpServletRequestBuilder clientRequest = get("/client-1")
				.param(OAuth2ParameterNames.CODE, "code")
				.param(OAuth2ParameterNames.STATE, "state")
				.with(authentication(authentication))
				.session(session);
		this.mockMvc.perform(clientRequest)
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/client-1"));
		// @formatter:on
		verify(requestCache).getRequest(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	// gh-5521
	@Test
	public void configureWhenCustomAuthorizationRequestResolverSetThenAuthorizationRequestIncludesCustomParameters()
			throws Exception {
		// Override default resolver
		OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver = authorizationRequestResolver;
		authorizationRequestResolver = mock(OAuth2AuthorizationRequestResolver.class);
		given(authorizationRequestResolver.resolve(any()))
			.willAnswer((invocation) -> defaultAuthorizationRequestResolver.resolve(invocation.getArgument(0)));
		this.spring.register(OAuth2ClientConfig.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/oauth2/authorization/registration-1"))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		// @formatter:on
		verify(authorizationRequestResolver).resolve(any());
	}

	@Test
	public void configureWhenCustomAuthorizationRedirectStrategySetThenAuthorizationRedirectStrategyUsed()
			throws Exception {
		authorizationRedirectStrategy = mock(RedirectStrategy.class);
		this.spring.register(OAuth2ClientConfig.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/oauth2/authorization/registration-1"))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on
		verify(authorizationRedirectStrategy).sendRedirect(any(), any(), anyString());
	}

	@Test
	public void configureWhenCustomAuthorizationRequestResolverBeanPresentThenAuthorizationRequestResolverUsed()
			throws Exception {
		OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver = authorizationRequestResolver;
		authorizationRequestResolver = mock(OAuth2AuthorizationRequestResolver.class);
		given(authorizationRequestResolver.resolve(any()))
			.willAnswer((invocation) -> defaultAuthorizationRequestResolver.resolve(invocation.getArgument(0)));
		this.spring.register(OAuth2ClientInLambdaConfig.class, AuthorizationRequestResolverConfig.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/oauth2/authorization/registration-1"))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		// @formatter:on
		verify(authorizationRequestResolver).resolve(any());
	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class OAuth2ClientConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.requestCache()
					.requestCache(requestCache)
					.and()
				.oauth2Client()
					.authorizationCodeGrant()
						.authorizationRequestResolver(authorizationRequestResolver)
						.authorizationRedirectStrategy(authorizationRedirectStrategy)
						.accessTokenResponseClient(accessTokenResponseClient);
			return http.build();
			// @formatter:on
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return clientRegistrationRepository;
		}

		@Bean
		OAuth2AuthorizedClientRepository authorizedClientRepository() {
			return authorizedClientRepository;
		}

		@RestController
		class ResourceController {

			@GetMapping("/resource1")
			String resource1(
					@RegisteredOAuth2AuthorizedClient("registration-1") OAuth2AuthorizedClient authorizedClient) {
				return "resource1";
			}

		}

	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class OAuth2ClientInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.oauth2Client(withDefaults());
			return http.build();
			// @formatter:on
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return clientRegistrationRepository;
		}

		@Bean
		OAuth2AuthorizedClientRepository authorizedClientRepository() {
			return authorizedClientRepository;
		}

	}

	@Configuration
	static class AuthorizationRequestResolverConfig {

		@Bean
		OAuth2AuthorizationRequestResolver authorizationRequestResolver() {
			return authorizationRequestResolver;
		}

	}

}
