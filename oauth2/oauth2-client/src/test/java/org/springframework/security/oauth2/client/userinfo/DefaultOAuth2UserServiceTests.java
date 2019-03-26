/*
 * Copyright 2002-2018 the original author or authors.
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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultOAuth2UserService}.
 *
 * @author Joe Grandja
 */
@PowerMockIgnore({"okhttp3.*", "okio.Buffer"})
@PrepareForTest(ClientRegistration.class)
@RunWith(PowerMockRunner.class)
public class DefaultOAuth2UserServiceTests {
	private ClientRegistration clientRegistration;
	private ClientRegistration.ProviderDetails providerDetails;
	private ClientRegistration.ProviderDetails.UserInfoEndpoint userInfoEndpoint;
	private OAuth2AccessToken accessToken;
	private DefaultOAuth2UserService userService = new DefaultOAuth2UserService();
	private MockWebServer server;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.clientRegistration = mock(ClientRegistration.class);
		this.providerDetails = mock(ClientRegistration.ProviderDetails.class);
		this.userInfoEndpoint = mock(ClientRegistration.ProviderDetails.UserInfoEndpoint.class);
		when(this.clientRegistration.getProviderDetails()).thenReturn(this.providerDetails);
		when(this.providerDetails.getUserInfoEndpoint()).thenReturn(this.userInfoEndpoint);
		this.accessToken = mock(OAuth2AccessToken.class);
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void setRequestEntityConverterWhenNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		this.userService.setRequestEntityConverter(null);
	}

	@Test
	public void setRestOperationsWhenNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		this.userService.setRestOperations(null);
	}

	@Test
	public void loadUserWhenUserRequestIsNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		this.userService.loadUser(null);
	}

	@Test
	public void loadUserWhenUserInfoUriIsNullThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("missing_user_info_uri"));

		when(this.userInfoEndpoint.getUri()).thenReturn(null);
		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	@Test
	public void loadUserWhenUserNameAttributeNameIsNullThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("missing_user_name_attribute"));

		when(this.userInfoEndpoint.getUri()).thenReturn("https://provider.com/user");
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn(null);
		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseThenReturnUser() {
		String userInfoResponse = "{\n" +
			"	\"user-name\": \"user1\",\n" +
			"   \"first-name\": \"first\",\n" +
			"   \"last-name\": \"last\",\n" +
			"   \"middle-name\": \"middle\",\n" +
			"   \"address\": \"address\",\n" +
			"   \"email\": \"user1@example.com\"\n" +
			"}\n";
		this.server.enqueue(jsonResponse(userInfoResponse));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.HEADER);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		OAuth2User user = this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));

		assertThat(user.getName()).isEqualTo("user1");
		assertThat(user.getAttributes().size()).isEqualTo(6);
		assertThat(user.getAttributes().get("user-name")).isEqualTo("user1");
		assertThat(user.getAttributes().get("first-name")).isEqualTo("first");
		assertThat(user.getAttributes().get("last-name")).isEqualTo("last");
		assertThat(user.getAttributes().get("middle-name")).isEqualTo("middle");
		assertThat(user.getAttributes().get("address")).isEqualTo("address");
		assertThat(user.getAttributes().get("email")).isEqualTo("user1@example.com");

		assertThat(user.getAuthorities().size()).isEqualTo(1);
		assertThat(user.getAuthorities().iterator().next()).isInstanceOf(OAuth2UserAuthority.class);
		OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) user.getAuthorities().iterator().next();
		assertThat(userAuthority.getAuthority()).isEqualTo("ROLE_USER");
		assertThat(userAuthority.getAttributes()).isEqualTo(user.getAttributes());
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseInvalidThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource"));

		String userInfoResponse = "{\n" +
			"	\"user-name\": \"user1\",\n" +
			"   \"first-name\": \"first\",\n" +
			"   \"last-name\": \"last\",\n" +
			"   \"middle-name\": \"middle\",\n" +
			"   \"address\": \"address\",\n" +
			"   \"email\": \"user1@example.com\"\n";
//			"}\n";		// Make the JSON invalid/malformed
		this.server.enqueue(jsonResponse(userInfoResponse));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.HEADER);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	@Test
	public void loadUserWhenUserInfoErrorResponseWwwAuthenticateHeaderThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource"));
		this.exception.expectMessage(containsString("Error Code: insufficient_scope, Error Description: The access token expired"));

		String wwwAuthenticateHeader = "Bearer realm=\"auth-realm\" error=\"insufficient_scope\" error_description=\"The access token expired\"";

		MockResponse response = new MockResponse();
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticateHeader);
		response.setResponseCode(400);
		this.server.enqueue(response);

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.HEADER);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	@Test
	public void loadUserWhenUserInfoErrorResponseThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource"));
		this.exception.expectMessage(containsString("Error Code: invalid_token"));

		String userInfoErrorResponse = "{\n" +
				"   \"error\": \"invalid_token\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(userInfoErrorResponse).setResponseCode(400));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.HEADER);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	@Test
	public void loadUserWhenServerErrorThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource: 500 Server Error"));

		this.server.enqueue(new MockResponse().setResponseCode(500));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.HEADER);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	@Test
	public void loadUserWhenUserInfoUriInvalidThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource"));

		String userInfoUri = "https://invalid-provider.com/user";

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.HEADER);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	// gh-5294
	@Test
	public void loadUserWhenUserInfoSuccessResponseThenAcceptHeaderJson() throws Exception {
		String userInfoResponse = "{\n" +
				"	\"user-name\": \"user1\",\n" +
				"   \"first-name\": \"first\",\n" +
				"   \"last-name\": \"last\",\n" +
				"   \"middle-name\": \"middle\",\n" +
				"   \"address\": \"address\",\n" +
				"   \"email\": \"user1@example.com\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(userInfoResponse));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.HEADER);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
		assertThat(this.server.takeRequest(1, TimeUnit.SECONDS).getHeader(HttpHeaders.ACCEPT))
				.isEqualTo(MediaType.APPLICATION_JSON_VALUE);
	}

	// gh-5500
	@Test
	public void loadUserWhenAuthenticationMethodHeaderSuccessResponseThenHttpMethodGet() throws Exception {
		String userInfoResponse = "{\n" +
				"	\"user-name\": \"user1\",\n" +
				"   \"first-name\": \"first\",\n" +
				"   \"last-name\": \"last\",\n" +
				"   \"middle-name\": \"middle\",\n" +
				"   \"address\": \"address\",\n" +
				"   \"email\": \"user1@example.com\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(userInfoResponse));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.HEADER);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
		RecordedRequest request = this.server.takeRequest();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.GET.name());
		assertThat(request.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(request.getHeader(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + this.accessToken.getTokenValue());
	}

	// gh-5500
	@Test
	public void loadUserWhenAuthenticationMethodFormSuccessResponseThenHttpMethodPost() throws Exception {
		String userInfoResponse = "{\n" +
				"	\"user-name\": \"user1\",\n" +
				"   \"first-name\": \"first\",\n" +
				"   \"last-name\": \"last\",\n" +
				"   \"middle-name\": \"middle\",\n" +
				"   \"address\": \"address\",\n" +
				"   \"email\": \"user1@example.com\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(userInfoResponse));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getAuthenticationMethod()).thenReturn(AuthenticationMethod.FORM);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn("user-name");
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
		RecordedRequest request = this.server.takeRequest();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.POST.name());
		assertThat(request.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(request.getHeader(HttpHeaders.CONTENT_TYPE)).contains(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		assertThat(request.getBody().readUtf8()).isEqualTo("access_token=" + this.accessToken.getTokenValue());
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
	}
}
