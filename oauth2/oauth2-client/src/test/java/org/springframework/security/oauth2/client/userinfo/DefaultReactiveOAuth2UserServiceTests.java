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

package org.springframework.security.oauth2.client.userinfo;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

/**
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 5.1
 */
public class DefaultReactiveOAuth2UserServiceTests {

	private ClientRegistration.Builder clientRegistration;

	private DefaultReactiveOAuth2UserService userService = new DefaultReactiveOAuth2UserService();

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
			Instant.now(), Instant.now().plus(Duration.ofDays(1)));

	private MockWebServer server;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String userInfoUri = this.server.url("/user").toString();
		// @formatter:off
		this.clientRegistration = TestClientRegistrations.clientRegistration()
				.userInfoUri(userInfoUri);
		// @formatter:on
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void loadUserWhenUserRequestIsNullThenThrowIllegalArgumentException() {
		OAuth2UserRequest request = null;
		StepVerifier.create(this.userService.loadUser(request)).expectError(IllegalArgumentException.class).verify();
	}

	@Test
	public void loadUserWhenUserInfoUriIsNullThenThrowOAuth2AuthenticationException() {
		this.clientRegistration.userInfoUri(null);
		StepVerifier.create(this.userService.loadUser(oauth2UserRequest())).expectErrorSatisfies((ex) -> assertThat(ex)
				.isInstanceOf(OAuth2AuthenticationException.class).hasMessageContaining("missing_user_info_uri"))
				.verify();
	}

	@Test
	public void loadUserWhenUserNameAttributeNameIsNullThenThrowOAuth2AuthenticationException() {
		this.clientRegistration.userNameAttributeName(null);
		// @formatter:off
		StepVerifier.create(this.userService.loadUser(oauth2UserRequest()))
				.expectErrorSatisfies((ex) -> assertThat(ex)
						.isInstanceOf(OAuth2AuthenticationException.class)
						.hasMessageContaining("missing_user_name_attribute")
				)
				.verify();
		// @formatter:on
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseThenReturnUser() {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"id\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		enqueueApplicationJsonBody(userInfoResponse);
		OAuth2User user = this.userService.loadUser(oauth2UserRequest()).block();
		assertThat(user.getName()).isEqualTo("user1");
		assertThat(user.getAttributes().size()).isEqualTo(6);
		assertThat((String) user.getAttribute("id")).isEqualTo("user1");
		assertThat((String) user.getAttribute("first-name")).isEqualTo("first");
		assertThat((String) user.getAttribute("last-name")).isEqualTo("last");
		assertThat((String) user.getAttribute("middle-name")).isEqualTo("middle");
		assertThat((String) user.getAttribute("address")).isEqualTo("address");
		assertThat((String) user.getAttribute("email")).isEqualTo("user1@example.com");
		assertThat(user.getAuthorities().size()).isEqualTo(1);
		assertThat(user.getAuthorities().iterator().next()).isInstanceOf(OAuth2UserAuthority.class);
		OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) user.getAuthorities().iterator().next();
		assertThat(userAuthority.getAuthority()).isEqualTo("ROLE_USER");
		assertThat(userAuthority.getAttributes()).isEqualTo(user.getAttributes());
	}

	@Test
	public void loadUserWhenUserInfo201CreatedResponseThenReturnUser() {
		// @formatter:off
		String userInfoResponse = "{\n"
				+ "   \"id\": \"user1\",\n"
				+ "   \"first-name\": \"first\",\n"
				+ "   \"last-name\": \"last\",\n"
				+ "   \"middle-name\": \"middle\",\n"
				+ "   \"address\": \"address\",\n"
				+ "   \"email\": \"user1@example.com\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(
				new MockResponse().setResponseCode(201).setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(userInfoResponse));
		assertThatNoException()
				.isThrownBy(() -> this.userService.loadUser(oauth2UserRequest()).block());
	}

	// gh-5500
	@Test
	public void loadUserWhenAuthenticationMethodHeaderSuccessResponseThenHttpMethodGet() throws Exception {
		this.clientRegistration.userInfoAuthenticationMethod(AuthenticationMethod.HEADER);
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"id\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		enqueueApplicationJsonBody(userInfoResponse);
		this.userService.loadUser(oauth2UserRequest()).block();
		RecordedRequest request = this.server.takeRequest();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.GET.name());
		assertThat(request.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(request.getHeader(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Bearer " + this.accessToken.getTokenValue());
	}

	// gh-5500
	@Test
	public void loadUserWhenAuthenticationMethodFormSuccessResponseThenHttpMethodPost() throws Exception {
		this.clientRegistration.userInfoAuthenticationMethod(AuthenticationMethod.FORM);
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"id\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		enqueueApplicationJsonBody(userInfoResponse);
		this.userService.loadUser(oauth2UserRequest()).block();
		RecordedRequest request = this.server.takeRequest();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.POST.name());
		assertThat(request.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(request.getHeader(HttpHeaders.CONTENT_TYPE)).contains(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		assertThat(request.getBody().readUtf8()).isEqualTo("access_token=" + this.accessToken.getTokenValue());
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseInvalidThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "	\"id\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n";
		// "}\n"; // Make the JSON invalid/malformed
		// @formatter:on
		enqueueApplicationJsonBody(userInfoResponse);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.userService.loadUser(oauth2UserRequest()).block())
				.withMessageContaining("invalid_user_info_response");
	}

	@Test
	public void loadUserWhenUserInfoErrorResponseThenThrowOAuth2AuthenticationException() {
		this.server.enqueue(new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setResponseCode(500).setBody("{}"));
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.userService.loadUser(oauth2UserRequest()).block())
				.withMessageContaining("invalid_user_info_response");
	}

	@Test
	public void loadUserWhenUserInfoUriInvalidThenThrowOAuth2AuthenticationException() {
		this.clientRegistration.userInfoUri("https://invalid-provider.com/user");
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.userService.loadUser(oauth2UserRequest()).block());
	}

	@Test
	public void loadUserWhenTokenContainsScopesThenIndividualScopeAuthorities() {
		Map<String, Object> body = new HashMap<>();
		body.put("id", "id");
		DefaultReactiveOAuth2UserService userService = withMockResponse(body);
		OAuth2UserRequest request = new OAuth2UserRequest(TestClientRegistrations.clientRegistration().build(),
				TestOAuth2AccessTokens.scopes("message:read", "message:write"));
		OAuth2User user = userService.loadUser(request).block();
		assertThat(user.getAuthorities()).hasSize(3);
		Iterator<? extends GrantedAuthority> authorities = user.getAuthorities().iterator();
		assertThat(authorities.next()).isInstanceOf(OAuth2UserAuthority.class);
		assertThat(authorities.next()).isEqualTo(new SimpleGrantedAuthority("SCOPE_message:read"));
		assertThat(authorities.next()).isEqualTo(new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void loadUserWhenTokenDoesNotContainScopesThenNoScopeAuthorities() {
		Map<String, Object> body = new HashMap<>();
		body.put("id", "id");
		DefaultReactiveOAuth2UserService userService = withMockResponse(body);
		OAuth2UserRequest request = new OAuth2UserRequest(TestClientRegistrations.clientRegistration().build(),
				TestOAuth2AccessTokens.noScopes());
		OAuth2User user = userService.loadUser(request).block();
		assertThat(user.getAuthorities()).hasSize(1);
		Iterator<? extends GrantedAuthority> authorities = user.getAuthorities().iterator();
		assertThat(authorities.next()).isInstanceOf(OAuth2UserAuthority.class);
	}

	// gh-8764
	@Test
	public void loadUserWhenUserInfoSuccessResponseInvalidContentTypeThenThrowOAuth2AuthenticationException() {
		MockResponse response = new MockResponse();
		response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE);
		response.setBody("invalid content type");
		this.server.enqueue(response);
		OAuth2UserRequest userRequest = oauth2UserRequest();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.userService.loadUser(userRequest).block()).withMessageContaining(
						"[invalid_user_info_response] An error occurred while attempting to "
								+ "retrieve the UserInfo Resource from '" + userRequest.getClientRegistration()
										.getProviderDetails().getUserInfoEndpoint().getUri()
								+ "': " + "response contains invalid content type 'text/plain'");
	}

	private DefaultReactiveOAuth2UserService withMockResponse(Map<String, Object> body) {
		WebClient real = WebClient.builder().build();
		WebClient.RequestHeadersUriSpec spec = spy(real.post());
		WebClient rest = spy(WebClient.class);
		WebClient.ResponseSpec clientResponse = mock(WebClient.ResponseSpec.class);
		given(rest.get()).willReturn(spec);
		given(spec.retrieve()).willReturn(clientResponse);
		given(clientResponse.onStatus(any(Predicate.class), any(Function.class))).willReturn(clientResponse);
		given(clientResponse.bodyToMono(any(ParameterizedTypeReference.class))).willReturn(Mono.just(body));
		DefaultReactiveOAuth2UserService userService = new DefaultReactiveOAuth2UserService();
		userService.setWebClient(rest);
		return userService;
	}

	private OAuth2UserRequest oauth2UserRequest() {
		return new OAuth2UserRequest(this.clientRegistration.build(), this.accessToken);
	}

	private void enqueueApplicationJsonBody(String json) {
		this.server.enqueue(
				new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json));
	}

}
