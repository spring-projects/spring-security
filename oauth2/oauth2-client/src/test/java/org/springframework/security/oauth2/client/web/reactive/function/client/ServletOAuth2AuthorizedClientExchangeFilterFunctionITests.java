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
package org.springframework.security.oauth2.client.web.reactive.function.client;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.blockhound.BlockHound;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

/**
 * @author Joe Grandja
 */
public class ServletOAuth2AuthorizedClientExchangeFilterFunctionITests {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	private ServletOAuth2AuthorizedClientExchangeFilterFunction authorizedClientFilter;
	private MockWebServer server;
	private String serverUrl;
	private WebClient webClient;
	private Authentication authentication;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;

	@BeforeClass
	public static void setUpBlockingChecks() {
		// IMPORTANT:
		// Before enabling BlockHound, we need to white-list `java.lang.Class.getPackage()`.
		// When the JVM loads `java.lang.Package.getSystemPackage()`, it attempts to
		// `java.lang.Package.loadManifest()` which is blocking I/O and triggers BlockHound to error.
		// NOTE: This is an issue with JDK 8. It's been tested on JDK 10 and works fine w/o this white-list.
		BlockHound.builder()
				.allowBlockingCallsInside(Class.class.getName(), "getPackage")
				.install();
	}

	@Before
	public void setUp() throws Exception {
		this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		final OAuth2AuthorizedClientRepository delegate = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
				new InMemoryOAuth2AuthorizedClientService(this.clientRegistrationRepository));
		this.authorizedClientRepository = spy(new OAuth2AuthorizedClientRepository() {
			@Override
			public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request) {
				return delegate.loadAuthorizedClient(clientRegistrationId, principal, request);
			}

			@Override
			public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal, HttpServletRequest request, HttpServletResponse response) {
				delegate.saveAuthorizedClient(authorizedClient, principal, request, response);
			}

			@Override
			public void removeAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request, HttpServletResponse response) {
				delegate.removeAuthorizedClient(clientRegistrationId, principal, request, response);
			}
		});
		this.authorizedClientFilter = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.authorizedClientFilter.afterPropertiesSet();
		this.server = new MockWebServer();
		this.server.start();
		this.serverUrl = this.server.url("/").toString();
		this.webClient = WebClient.builder()
				.apply(this.authorizedClientFilter.oauth2Configuration())
				.build();
		this.authentication = new TestingAuthenticationToken("principal", "password");
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(this.request, this.response));
	}

	@After
	public void cleanup() throws Exception {
		this.authorizedClientFilter.destroy();
		this.server.shutdown();
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	public void requestWhenNotAuthorizedThenAuthorizeAndSendRequest() {
		String accessTokenResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\",\n" +
				"   \"scope\": \"read write\"\n" +
				"}\n";
		String clientResponse = "{\n" +
				"	\"attribute1\": \"value1\",\n" +
				"	\"attribute2\": \"value2\"\n" +
				"}\n";

		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));

		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().tokenUri(this.serverUrl).build();
		when(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration.getRegistrationId()))).thenReturn(clientRegistration);

		this.webClient
				.get()
				.uri(this.serverUrl)
				.attributes(clientRegistrationId(clientRegistration.getRegistrationId()))
				.retrieve()
				.bodyToMono(String.class)
				.block();

		assertThat(this.server.getRequestCount()).isEqualTo(2);

		ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor = ArgumentCaptor.forClass(OAuth2AuthorizedClient.class);
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				authorizedClientCaptor.capture(), eq(this.authentication), eq(this.request), eq(this.response));
		assertThat(authorizedClientCaptor.getValue().getClientRegistration()).isSameAs(clientRegistration);
	}

	@Test
	public void requestWhenAuthorizedButExpiredThenRefreshAndSendRequest() {
		String accessTokenResponse = "{\n" +
				"	\"access_token\": \"refreshed-access-token\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\"\n" +
				"}\n";
		String clientResponse = "{\n" +
				"	\"attribute1\": \"value1\",\n" +
				"	\"attribute2\": \"value2\"\n" +
				"}\n";

		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));

		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().tokenUri(this.serverUrl).build();
		when(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration.getRegistrationId()))).thenReturn(clientRegistration);

		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"expired-access-token", issuedAt, expiresAt, new HashSet<>(Arrays.asList("read", "write")));
		OAuth2RefreshToken refreshToken = TestOAuth2RefreshTokens.refreshToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				clientRegistration, this.authentication.getName(), accessToken, refreshToken);
		doReturn(authorizedClient).when(this.authorizedClientRepository).loadAuthorizedClient(
				eq(clientRegistration.getRegistrationId()), eq(this.authentication), eq(this.request));

		this.webClient
				.get()
				.uri(this.serverUrl)
				.attributes(clientRegistrationId(clientRegistration.getRegistrationId()))
				.retrieve()
				.bodyToMono(String.class)
				.block();

		assertThat(this.server.getRequestCount()).isEqualTo(2);

		ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor = ArgumentCaptor.forClass(OAuth2AuthorizedClient.class);
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				authorizedClientCaptor.capture(), eq(this.authentication), eq(this.request), eq(this.response));
		OAuth2AuthorizedClient refreshedAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(refreshedAuthorizedClient.getClientRegistration()).isSameAs(clientRegistration);
		assertThat(refreshedAuthorizedClient.getAccessToken().getTokenValue()).isEqualTo("refreshed-access-token");
	}

	@Test
	public void requestMultipleWhenNoneAuthorizedThenAuthorizeAndSendRequest() {
		String accessTokenResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\",\n" +
				"   \"scope\": \"read write\"\n" +
				"}\n";
		String clientResponse = "{\n" +
				"	\"attribute1\": \"value1\",\n" +
				"	\"attribute2\": \"value2\"\n" +
				"}\n";

		// Client 1
		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));

		ClientRegistration clientRegistration1 = TestClientRegistrations.clientCredentials()
				.registrationId("client-1").tokenUri(this.serverUrl).build();
		when(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration1.getRegistrationId()))).thenReturn(clientRegistration1);

		// Client 2
		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));

		ClientRegistration clientRegistration2 = TestClientRegistrations.clientCredentials()
				.registrationId("client-2").tokenUri(this.serverUrl).build();
		when(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration2.getRegistrationId()))).thenReturn(clientRegistration2);

		this.webClient
				.get()
				.uri(this.serverUrl)
				.attributes(clientRegistrationId(clientRegistration1.getRegistrationId()))
				.retrieve()
				.bodyToMono(String.class)
				.flatMap(response -> this.webClient
						.get()
						.uri(this.serverUrl)
						.attributes(clientRegistrationId(clientRegistration2.getRegistrationId()))
						.retrieve()
						.bodyToMono(String.class))
				.block();

		assertThat(this.server.getRequestCount()).isEqualTo(4);

		ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor = ArgumentCaptor.forClass(OAuth2AuthorizedClient.class);
		verify(this.authorizedClientRepository, times(2)).saveAuthorizedClient(
				authorizedClientCaptor.capture(), eq(this.authentication), eq(this.request), eq(this.response));
		assertThat(authorizedClientCaptor.getAllValues().get(0).getClientRegistration()).isSameAs(clientRegistration1);
		assertThat(authorizedClientCaptor.getAllValues().get(1).getClientRegistration()).isSameAs(clientRegistration2);
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
	}
}
