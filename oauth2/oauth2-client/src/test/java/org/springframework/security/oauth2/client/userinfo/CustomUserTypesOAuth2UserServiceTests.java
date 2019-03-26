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
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link CustomUserTypesOAuth2UserService}.
 *
 * @author Joe Grandja
 */
@PowerMockIgnore("okhttp3.*")
@PrepareForTest(ClientRegistration.class)
@RunWith(PowerMockRunner.class)
public class CustomUserTypesOAuth2UserServiceTests {
	private ClientRegistration clientRegistration;
	private ClientRegistration.ProviderDetails providerDetails;
	private ClientRegistration.ProviderDetails.UserInfoEndpoint userInfoEndpoint;
	private OAuth2AccessToken accessToken;
	private CustomUserTypesOAuth2UserService userService;
	private MockWebServer server;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setUp() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.clientRegistration = mock(ClientRegistration.class);
		this.providerDetails = mock(ClientRegistration.ProviderDetails.class);
		this.userInfoEndpoint = mock(ClientRegistration.ProviderDetails.UserInfoEndpoint.class);
		when(this.clientRegistration.getProviderDetails()).thenReturn(this.providerDetails);
		when(this.providerDetails.getUserInfoEndpoint()).thenReturn(this.userInfoEndpoint);
		String registrationId = "client-registration-id-1";
		when(this.clientRegistration.getRegistrationId()).thenReturn(registrationId);
		this.accessToken = mock(OAuth2AccessToken.class);

		Map<String, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();
		customUserTypes.put(registrationId, CustomOAuth2User.class);
		this.userService = new CustomUserTypesOAuth2UserService(customUserTypes);
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void constructorWhenCustomUserTypesIsNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		new CustomUserTypesOAuth2UserService(null);
	}

	@Test
	public void constructorWhenCustomUserTypesIsEmptyThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		new CustomUserTypesOAuth2UserService(Collections.emptyMap());
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
	public void loadUserWhenCustomUserTypeNotFoundThenReturnNull() {
		when(this.clientRegistration.getRegistrationId()).thenReturn("other-client-registration-id-1");

		OAuth2User user = this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
		assertThat(user).isNull();
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseThenReturnUser() {
		String userInfoResponse = "{\n" +
			"	\"id\": \"12345\",\n" +
			"   \"name\": \"first last\",\n" +
			"   \"login\": \"user1\",\n" +
			"   \"email\": \"user1@example.com\"\n" +
			"}\n";
		this.server.enqueue(jsonResponse(userInfoResponse));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		OAuth2User user = this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));

		assertThat(user.getName()).isEqualTo("first last");
		assertThat(user.getAttributes().size()).isEqualTo(4);
		assertThat(user.getAttributes().get("id")).isEqualTo("12345");
		assertThat(user.getAttributes().get("name")).isEqualTo("first last");
		assertThat(user.getAttributes().get("login")).isEqualTo("user1");
		assertThat(user.getAttributes().get("email")).isEqualTo("user1@example.com");

		assertThat(user.getAuthorities().size()).isEqualTo(1);
		assertThat(user.getAuthorities().iterator().next().getAuthority()).isEqualTo("ROLE_USER");
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseInvalidThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource"));

		String userInfoResponse = "{\n" +
			"	\"id\": \"12345\",\n" +
			"   \"name\": \"first last\",\n" +
			"   \"login\": \"user1\",\n" +
			"   \"email\": \"user1@example.com\"\n";
//			"}\n";		// Make the JSON invalid/malformed
		this.server.enqueue(jsonResponse(userInfoResponse));

		String userInfoUri = this.server.url("/user").toString();

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
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
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	@Test
	public void loadUserWhenUserInfoUriInvalidThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource"));

		String userInfoUri = "https://invalid-provider.com/user";

		when(this.userInfoEndpoint.getUri()).thenReturn(userInfoUri);
		when(this.accessToken.getTokenValue()).thenReturn("access-token");

		this.userService.loadUser(new OAuth2UserRequest(this.clientRegistration, this.accessToken));
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
	}

	public static class CustomOAuth2User implements OAuth2User {
		private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		private String id;
		private String name;
		private String login;
		private String email;

		public CustomOAuth2User() {
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return this.authorities;
		}

		@Override
		public Map<String, Object> getAttributes() {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put("id", this.getId());
			attributes.put("name", this.getName());
			attributes.put("login", this.getLogin());
			attributes.put("email", this.getEmail());
			return attributes;
		}

		public String getId() {
			return this.id;
		}

		public void setId(String id) {
			this.id = id;
		}

		@Override
		public String getName() {
			return this.name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getLogin() {
			return this.login;
		}

		public void setLogin(String login) {
			this.login = login;
		}

		public String getEmail() {
			return this.email;
		}

		public void setEmail(String email) {
			this.email = email;
		}
	}
}
