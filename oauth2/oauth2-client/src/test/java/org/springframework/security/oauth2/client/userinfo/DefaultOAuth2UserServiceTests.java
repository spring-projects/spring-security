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

package org.springframework.security.oauth2.client.userinfo;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
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
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link DefaultOAuth2UserService}.
 *
 * @author Joe Grandja
 * @author Eddú Meléndez
 */
public class DefaultOAuth2UserServiceTests {

	private ClientRegistration.Builder clientRegistrationBuilder;

	private OAuth2AccessToken accessToken;

	private DefaultOAuth2UserService userService = new DefaultOAuth2UserService();

	private MockWebServer server;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		// @formatter:off
		this.clientRegistrationBuilder = TestClientRegistrations.clientRegistration()
				.userInfoUri(null)
				.userNameAttributeName(null);
		// @formatter:on
		this.accessToken = TestOAuth2AccessTokens.noScopes();
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void setRequestEntityConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userService.setRequestEntityConverter(null));
	}

	@Test
	public void setRestOperationsWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userService.setRestOperations(null));
	}

	@Test
	public void loadUserWhenUserRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userService.loadUser(null));
	}

	@Test
	public void loadUserWhenUserInfoUriIsNullThenThrowOAuth2AuthenticationException() {
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken)))
			.withMessageContaining("missing_user_info_uri");
	}

	@Test
	public void loadUserWhenUserNameAttributeNameIsNullThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		ClientRegistration clientRegistration = this.clientRegistrationBuilder
				.userInfoUri("https://provider.com/user")
				.build();
		// @formatter:on
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken)))
			.withMessageContaining("missing_user_name_attribute");
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseThenReturnUser() {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"user-name\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		OAuth2User user = this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken));
		assertThat(user.getName()).isEqualTo("user1");
		assertThat(user.getAttributes()).hasSize(6);
		assertThat((String) user.getAttribute("user-name")).isEqualTo("user1");
		assertThat((String) user.getAttribute("first-name")).isEqualTo("first");
		assertThat((String) user.getAttribute("last-name")).isEqualTo("last");
		assertThat((String) user.getAttribute("middle-name")).isEqualTo("middle");
		assertThat((String) user.getAttribute("address")).isEqualTo("address");
		assertThat((String) user.getAttribute("email")).isEqualTo("user1@example.com");
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isInstanceOf(OAuth2UserAuthority.class);
		OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) user.getAuthorities().iterator().next();
		assertThat(userAuthority.getAuthority()).isEqualTo("OAUTH2_USER");
		assertThat(userAuthority.getAttributes()).isEqualTo(user.getAttributes());
		assertThat(userAuthority.getUserNameAttributeName()).isEqualTo("user-name");
	}

	@Test
	public void loadUserWhenNestedUserInfoSuccessThenReturnUser() {
		// @formatter:off
		String userInfoResponse = "{\n"
				+ "   \"user\": {\"user-name\": \"user1\"},\n"
				+ "   \"first-name\": \"first\",\n"
				+ "   \"last-name\": \"last\",\n"
				+ "   \"middle-name\": \"middle\",\n"
				+ "   \"address\": \"address\",\n"
				+ "   \"email\": \"user1@example.com\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		DefaultOAuth2UserService userService = new DefaultOAuth2UserService();
		userService.setAttributesConverter((request) -> (attributes) -> {
			Map<String, Object> user = (Map<String, Object>) attributes.get("user");
			attributes.put("user-name", user.get("user-name"));
			return attributes;
		});
		OAuth2User user = userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken));
		assertThat(user.getName()).isEqualTo("user1");
		assertThat(user.getAttributes()).hasSize(7);
		assertThat(((Map<?, ?>) user.getAttribute("user")).get("user-name")).isEqualTo("user1");
		assertThat((String) user.getAttribute("first-name")).isEqualTo("first");
		assertThat((String) user.getAttribute("last-name")).isEqualTo("last");
		assertThat((String) user.getAttribute("middle-name")).isEqualTo("middle");
		assertThat((String) user.getAttribute("address")).isEqualTo("address");
		assertThat((String) user.getAttribute("email")).isEqualTo("user1@example.com");
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isInstanceOf(OAuth2UserAuthority.class);
		OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) user.getAuthorities().iterator().next();
		assertThat(userAuthority.getAuthority()).isEqualTo("OAUTH2_USER");
		assertThat(userAuthority.getAttributes()).isEqualTo(user.getAttributes());
		assertThat(userAuthority.getUserNameAttributeName()).isEqualTo("user-name");
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseInvalidThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "	\"user-name\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n";
		// "}\n"; // Make the JSON invalid/malformed
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource");
	}

	@Test
	public void loadUserWhenUserInfoErrorResponseWwwAuthenticateHeaderThenThrowOAuth2AuthenticationException() {
		String wwwAuthenticateHeader = "Bearer realm=\"auth-realm\" error=\"insufficient_scope\" error_description=\"The access token expired\"";
		MockResponse response = new MockResponse();
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticateHeader);
		response.setResponseCode(400);
		this.server.enqueue(response);
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource")
			.withMessageContaining("Error Code: insufficient_scope, Error Description: The access token expired");
	}

	@Test
	public void loadUserWhenUserInfoErrorResponseThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		String userInfoErrorResponse = "{\n"
				+ "   \"error\": \"invalid_token\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoErrorResponse).setResponseCode(400));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource")
			.withMessageContaining("Error Code: invalid_token");
	}

	@Test
	public void loadUserWhenServerErrorThenThrowOAuth2AuthenticationException() {
		this.server.enqueue(new MockResponse().setResponseCode(500));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource: 500 Server Error");
	}

	@Test
	public void loadUserWhenUserInfoUriInvalidThenThrowOAuth2AuthenticationException() {
		String userInfoUri = "https://invalid-provider.com/user";
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource");
	}

	// gh-5294
	@Test
	public void loadUserWhenUserInfoSuccessResponseThenAcceptHeaderJson() throws Exception {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"user-name\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken));
		assertThat(this.server.takeRequest(1, TimeUnit.SECONDS).getHeader(HttpHeaders.ACCEPT))
			.isEqualTo(MediaType.APPLICATION_JSON_VALUE);
	}

	// gh-5500
	@Test
	public void loadUserWhenAuthenticationMethodHeaderSuccessResponseThenHttpMethodGet() throws Exception {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"user-name\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken));
		RecordedRequest request = this.server.takeRequest();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.GET.name());
		assertThat(request.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(request.getHeader(HttpHeaders.AUTHORIZATION))
			.isEqualTo("Bearer " + this.accessToken.getTokenValue());
	}

	// gh-5500
	@Test
	public void loadUserWhenAuthenticationMethodFormSuccessResponseThenHttpMethodPost() throws Exception {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"user-name\": \"user1\",\n"
			+ "   \"first-name\": \"first\",\n"
			+ "   \"last-name\": \"last\",\n"
			+ "   \"middle-name\": \"middle\",\n"
			+ "   \"address\": \"address\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.userNameAttributeName("user-name")
			.build();
		this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken));
		RecordedRequest request = this.server.takeRequest();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.POST.name());
		assertThat(request.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(request.getHeader(HttpHeaders.CONTENT_TYPE)).contains(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		assertThat(request.getBody().readUtf8()).isEqualTo("access_token=" + this.accessToken.getTokenValue());
	}

	@Test
	public void loadUserWhenTokenContainsScopesThenIndividualScopeAuthorities() {
		Map<String, Object> body = new HashMap<>();
		body.put("id", "id");
		DefaultOAuth2UserService userService = withMockResponse(body);
		OAuth2UserRequest request = new OAuth2UserRequest(TestClientRegistrations.clientRegistration().build(),
				TestOAuth2AccessTokens.scopes("message:read", "message:write"));
		OAuth2User user = userService.loadUser(request);
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
		DefaultOAuth2UserService userService = withMockResponse(body);
		OAuth2UserRequest request = new OAuth2UserRequest(TestClientRegistrations.clientRegistration().build(),
				TestOAuth2AccessTokens.noScopes());
		OAuth2User user = userService.loadUser(request);
		assertThat(user.getAuthorities()).hasSize(1);
		Iterator<? extends GrantedAuthority> authorities = user.getAuthorities().iterator();
		assertThat(authorities.next()).isInstanceOf(OAuth2UserAuthority.class);
	}

	// gh-8764
	@Test
	public void loadUserWhenUserInfoSuccessResponseInvalidContentTypeThenThrowOAuth2AuthenticationException() {
		String userInfoUri = this.server.url("/user").toString();
		MockResponse response = new MockResponse();
		response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE);
		response.setBody("invalid content type");
		this.server.enqueue(response);
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName("user-name")
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(new OAuth2UserRequest(clientRegistration, this.accessToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource "
							+ "from '" + userInfoUri + "': response contains invalid content type 'text/plain'.");
	}

	@Test
	public void setAttributesConverterWhenNullThenException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.userService.setAttributesConverter(null));
	}

	private DefaultOAuth2UserService withMockResponse(Map<String, Object> response) {
		ResponseEntity<Map<String, Object>> responseEntity = new ResponseEntity<>(response, HttpStatus.OK);
		Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter = mock(Converter.class);
		RestOperations rest = mock(RestOperations.class);
		given(rest.exchange(nullable(RequestEntity.class), any(ParameterizedTypeReference.class)))
			.willReturn(responseEntity);
		DefaultOAuth2UserService userService = new DefaultOAuth2UserService();
		userService.setRequestEntityConverter(requestEntityConverter);
		userService.setRestOperations(rest);
		return userService;
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json);
	}

}
