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
package org.springframework.security.oauth2.client.oidc.userinfo;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OidcUserService}.
 *
 * @author Joe Grandja
 */
@PowerMockIgnore("okhttp3.*")
@PrepareForTest(ClientRegistration.class)
@RunWith(PowerMockRunner.class)
public class OidcUserServiceTests {
	private ClientRegistration clientRegistration;
	private ClientRegistration.ProviderDetails providerDetails;
	private ClientRegistration.ProviderDetails.UserInfoEndpoint userInfoEndpoint;
	private OAuth2AccessToken accessToken;
	private OidcIdToken idToken;
	private OidcUserService userService = new OidcUserService();

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setUp() throws Exception {
		this.clientRegistration = mock(ClientRegistration.class);
		this.providerDetails = mock(ClientRegistration.ProviderDetails.class);
		this.userInfoEndpoint = mock(ClientRegistration.ProviderDetails.UserInfoEndpoint.class);
		when(this.clientRegistration.getProviderDetails()).thenReturn(this.providerDetails);
		when(this.providerDetails.getUserInfoEndpoint()).thenReturn(this.userInfoEndpoint);
		when(this.clientRegistration.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);

		this.accessToken = mock(OAuth2AccessToken.class);
		Set<String> authorizedScopes = new LinkedHashSet<>(Arrays.asList(OidcScopes.OPENID, OidcScopes.PROFILE));
		when(this.accessToken.getScopes()).thenReturn(authorizedScopes);

		this.idToken = mock(OidcIdToken.class);
		Map<String, Object> idTokenClaims = new HashMap<>();
		idTokenClaims.put(IdTokenClaimNames.ISS, "https://provider.com");
		idTokenClaims.put(IdTokenClaimNames.SUB, "subject1");
		when(this.idToken.getClaims()).thenReturn(idTokenClaims);
		when(this.idToken.getSubject()).thenReturn("subject1");
	}

	@Test
	public void loadUserWhenUserRequestIsNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		this.userService.loadUser(null);
	}

	@Test
	public void loadUserWhenUserInfoUriIsNullThenUserInfoEndpointNotRequested() {
		when(this.userInfoEndpoint.getUri()).thenReturn(null);

		OidcUser user = this.userService.loadUser(
			new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));
		assertThat(user.getUserInfo()).isNull();
	}

	@Test
	public void loadUserWhenAuthorizedScopesDoesNotContainUserInfoScopesThenUserInfoEndpointNotRequested() {
		Set<String> authorizedScopes = new LinkedHashSet<>(Arrays.asList("scope1", "scope2"));
		when(this.accessToken.getScopes()).thenReturn(authorizedScopes);

		when(this.userInfoEndpoint.getUri()).thenReturn("https://provider.com/user");

		OidcUser user = this.userService.loadUser(
			new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));
		assertThat(user.getUserInfo()).isNull();
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseThenReturnUser() throws Exception {
		MockWebServer server = new MockWebServer();

		String userInfoResponse = "{\n" +
			"	\"sub\": \"subject1\",\n" +
			"   \"name\": \"first last\",\n" +
			"   \"given_name\": \"first\",\n" +
			"   \"family_name\": \"last\",\n" +
			"   \"preferred_username\": \"user1\",\n" +
			"   \"email\": \"user1@example.com\"\n" +
			"}\n";
		server.enqueue(new MockResponse()
			.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
			.setBody(userInfoResponse));

		server.start();

		String userInfoUri = server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		OidcUser user = this.userService.loadUser(
			new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));

		server.shutdown();

		assertThat(user.getIdToken()).isNotNull();
		assertThat(user.getUserInfo()).isNotNull();
		assertThat(user.getUserInfo().getClaims().size()).isEqualTo(6);
		assertThat(user.getIdToken()).isEqualTo(this.idToken);
		assertThat(user.getName()).isEqualTo("subject1");
		assertThat(user.getUserInfo().getSubject()).isEqualTo("subject1");
		assertThat(user.getUserInfo().getFullName()).isEqualTo("first last");
		assertThat(user.getUserInfo().getGivenName()).isEqualTo("first");
		assertThat(user.getUserInfo().getFamilyName()).isEqualTo("last");
		assertThat(user.getUserInfo().getPreferredUsername()).isEqualTo("user1");
		assertThat(user.getUserInfo().getEmail()).isEqualTo("user1@example.com");

		assertThat(user.getAuthorities().size()).isEqualTo(1);
		assertThat(user.getAuthorities().iterator().next()).isInstanceOf(OidcUserAuthority.class);
		OidcUserAuthority userAuthority = (OidcUserAuthority) user.getAuthorities().iterator().next();
		assertThat(userAuthority.getAuthority()).isEqualTo("ROLE_USER");
		assertThat(userAuthority.getIdToken()).isEqualTo(user.getIdToken());
		assertThat(userAuthority.getUserInfo()).isEqualTo(user.getUserInfo());
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseAndUserInfoSubjectNotSameAsIdTokenSubjectThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_user_info_response"));

		MockWebServer server = new MockWebServer();

		String userInfoResponse = "{\n" +
			"	\"sub\": \"other-subject\"\n" +
			"}\n";
		server.enqueue(new MockResponse()
			.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
			.setBody(userInfoResponse));

		server.start();

		String userInfoUri = server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		try {
			this.userService.loadUser(new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));
		} finally {
			server.shutdown();
		}
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseInvalidThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_user_info_response"));

		MockWebServer server = new MockWebServer();

		String userInfoResponse = "{\n" +
			"	\"sub\": \"subject1\",\n" +
			"   \"name\": \"first last\",\n" +
			"   \"given_name\": \"first\",\n" +
			"   \"family_name\": \"last\",\n" +
			"   \"preferred_username\": \"user1\",\n" +
			"   \"email\": \"user1@example.com\"\n";
//			"}\n";		// Make the JSON invalid/malformed
		server.enqueue(new MockResponse()
			.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
			.setBody(userInfoResponse));

		server.start();

		String userInfoUri = server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		try {
			this.userService.loadUser(new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));
		} finally {
			server.shutdown();
		}
	}

	@Test
	public void loadUserWhenUserInfoErrorResponseThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_user_info_response"));

		MockWebServer server = new MockWebServer();
		server.enqueue(new MockResponse().setResponseCode(500));
		server.start();

		String userInfoUri = server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		try {
			this.userService.loadUser(new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));
		} finally {
			server.shutdown();
		}
	}

	@Test
	public void loadUserWhenUserInfoUriInvalidThenThrowAuthenticationServiceException() throws Exception {
		this.exception.expect(AuthenticationServiceException.class);

		String userInfoUri = "https://invalid-provider.com/user";

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));
	}

	@Test
	public void loadUserWhenCustomUserNameAttributeNameThenGetNameReturnsCustomUserName() throws Exception {
		MockWebServer server = new MockWebServer();

		String userInfoResponse = "{\n" +
			"	\"sub\": \"subject1\",\n" +
			"   \"name\": \"first last\",\n" +
			"   \"given_name\": \"first\",\n" +
			"   \"family_name\": \"last\",\n" +
			"   \"preferred_username\": \"user1\",\n" +
			"   \"email\": \"user1@example.com\"\n" +
			"}\n";
		server.enqueue(new MockResponse()
			.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
			.setBody(userInfoResponse));

		server.start();

		String userInfoUri = server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.userInfoEndpoint.getUserNameAttributeName()).thenReturn(StandardClaimNames.EMAIL);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		OidcUser user = this.userService.loadUser(
			new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));

		server.shutdown();

		assertThat(user.getName()).isEqualTo("user1@example.com");
	}

	// gh-5294
	@Test
	public void loadUserWhenUserInfoSuccessResponseThenAcceptHeaderJson() throws Exception {
		MockWebServer server = new MockWebServer();

		String userInfoResponse = "{\n" +
				"	\"sub\": \"subject1\",\n" +
				"   \"name\": \"first last\",\n" +
				"   \"given_name\": \"first\",\n" +
				"   \"family_name\": \"last\",\n" +
				"   \"preferred_username\": \"user1\",\n" +
				"   \"email\": \"user1@example.com\"\n" +
				"}\n";
		server.enqueue(new MockResponse()
				.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.setBody(userInfoResponse));

		server.start();

		String userInfoUri = server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OidcUserRequest(this.clientRegistration, this.accessToken, this.idToken));
		server.shutdown();
		assertThat(server.takeRequest(1, TimeUnit.SECONDS).getHeader(HttpHeaders.ACCEPT))
				.isEqualTo(MediaType.APPLICATION_JSON_VALUE);
	}
}
