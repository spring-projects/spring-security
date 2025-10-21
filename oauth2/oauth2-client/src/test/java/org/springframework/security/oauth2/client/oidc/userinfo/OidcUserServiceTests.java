/*
 * Copyright 2004-present the original author or authors.
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

import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OidcUserService}.
 *
 * @author Joe Grandja
 */
public class OidcUserServiceTests {

	private ClientRegistration.Builder clientRegistrationBuilder;

	private OAuth2AccessToken accessToken;

	private OidcIdToken idToken;

	private OidcUserService userService = new OidcUserService();

	private MockWebServer server;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.clientRegistrationBuilder = TestClientRegistrations.clientRegistration()
			.userInfoUri(null)
			.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
			.userNameAttributeName(StandardClaimNames.SUB);
		this.accessToken = TestOAuth2AccessTokens.scopes(OidcScopes.OPENID, OidcScopes.PROFILE);
		Map<String, Object> idTokenClaims = new HashMap<>();
		idTokenClaims.put(IdTokenClaimNames.ISS, "https://provider.com");
		idTokenClaims.put(IdTokenClaimNames.SUB, "subject1");
		this.idToken = new OidcIdToken("access-token", Instant.MIN, Instant.MAX, idTokenClaims);
		this.userService.setOauth2UserService(new DefaultOAuth2UserService());
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void createDefaultClaimTypeConvertersWhenCalledThenDefaultsAreCorrect() {
		Map<String, Converter<Object, ?>> claimTypeConverters = OidcUserService.createDefaultClaimTypeConverters();
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.EMAIL_VERIFIED);
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.PHONE_NUMBER_VERIFIED);
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.UPDATED_AT);
	}

	@Test
	public void setOauth2UserServiceWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userService.setOauth2UserService(null));
	}

	@Test
	public void setClaimTypeConverterFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userService.setClaimTypeConverterFactory(null));
	}

	@Test
	public void setRetrieveUserInfoWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.userService.setRetrieveUserInfo(null))
				.withMessage("retrieveUserInfo cannot be null");
		// @formatter:on
	}

	@Test
	public void setOidcUserConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.userService.setOidcUserConverter(null))
				.withMessage("oidcUserConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void loadUserWhenUserRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userService.loadUser(null));
	}

	@Test
	public void loadUserWhenUserInfoUriIsNullThenUserInfoEndpointNotRequested() {
		OidcUser user = this.userService
			.loadUser(new OidcUserRequest(this.clientRegistrationBuilder.build(), this.accessToken, this.idToken));
		assertThat(user.getUserInfo()).isNull();
	}

	@Test
	public void loadUserWhenCustomRetrieveUserInfoSetThenUsed() {
		// @formatter:off
		String userInfoResponse = "{\n"
				+ "   \"sub\": \"subject1\",\n"
				+ "   \"name\": \"first last\",\n"
				+ "   \"given_name\": \"first\",\n"
				+ "   \"family_name\": \"last\",\n"
				+ "   \"preferred_username\": \"user1\",\n"
				+ "   \"email\": \"user1@example.com\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		this.accessToken = TestOAuth2AccessTokens.noScopes();
		Predicate<OidcUserRequest> customRetrieveUserInfo = mock(Predicate.class);
		given(customRetrieveUserInfo.test(any(OidcUserRequest.class))).willReturn(true);
		this.userService.setRetrieveUserInfo(customRetrieveUserInfo);
		OidcUser user = this.userService
			.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken));
		assertThat(user.getUserInfo()).isNotNull();
	}

	@Test
	public void loadUserWhenCustomOidcUserConverterSetThenUsed() {
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri("https://example.com/user")
			.build();
		this.accessToken = TestOAuth2AccessTokens.noScopes();
		Converter<OidcUserSource, OidcUser> oidcUserConverter = mock(Converter.class);
		String nameAttributeKey = IdTokenClaimNames.SUB;
		OidcUser actualUser = new DefaultOidcUser(AuthorityUtils.createAuthorityList("a", "b"), this.idToken,
				nameAttributeKey);
		OAuth2User oauth2User = new DefaultOAuth2User(actualUser.getAuthorities(), actualUser.getClaims(),
				nameAttributeKey);
		OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2 = mock(OAuth2UserService.class);
		given(oauth2.loadUser(any())).willReturn(oauth2User);
		given(oidcUserConverter.convert(any())).willReturn(actualUser);
		this.userService.setOauth2UserService(oauth2);
		this.userService.setOidcUserConverter(oidcUserConverter);
		OidcUserRequest userRequest = new OidcUserRequest(clientRegistration, this.accessToken, this.idToken);
		OidcUser user = this.userService.loadUser(userRequest);
		assertThat(user).isEqualTo(actualUser);
		ArgumentCaptor<OidcUserSource> metadataCptr = ArgumentCaptor.forClass(OidcUserSource.class);
		verify(oidcUserConverter).convert(metadataCptr.capture());
		OidcUserSource metadata = metadataCptr.getValue();
		assertThat(metadata.getUserRequest()).isEqualTo(userRequest);
		assertThat(metadata.getOauth2User()).isEqualTo(oauth2User);
		assertThat(metadata.getUserInfo()).isNotNull();
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseThenReturnUser() {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"sub\": \"subject1\",\n"
			+ "   \"name\": \"first last\",\n"
			+ "   \"given_name\": \"first\",\n"
			+ "   \"family_name\": \"last\",\n"
			+ "   \"preferred_username\": \"user1\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		OidcUser user = this.userService
			.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken));
		assertThat(user.getIdToken()).isNotNull();
		assertThat(user.getUserInfo()).isNotNull();
		assertThat(user.getUserInfo().getClaims()).hasSize(6);
		assertThat(user.getIdToken()).isEqualTo(this.idToken);
		assertThat(user.getName()).isEqualTo("subject1");
		assertThat(user.getUserInfo().getSubject()).isEqualTo("subject1");
		assertThat(user.getUserInfo().getFullName()).isEqualTo("first last");
		assertThat(user.getUserInfo().getGivenName()).isEqualTo("first");
		assertThat(user.getUserInfo().getFamilyName()).isEqualTo("last");
		assertThat(user.getUserInfo().getPreferredUsername()).isEqualTo("user1");
		assertThat(user.getUserInfo().getEmail()).isEqualTo("user1@example.com");
		assertThat(user.getAuthorities()).hasSize(3);
		assertThat(user.getAuthorities().iterator().next()).isInstanceOf(OidcUserAuthority.class);
		OidcUserAuthority userAuthority = (OidcUserAuthority) user.getAuthorities().iterator().next();
		assertThat(userAuthority.getAuthority()).isEqualTo("OIDC_USER");
		assertThat(userAuthority.getIdToken()).isEqualTo(user.getIdToken());
		assertThat(userAuthority.getUserInfo()).isEqualTo(user.getUserInfo());
	}

	// gh-5447
	@Test
	public void loadUserWhenUserInfoSuccessResponseAndUserInfoSubjectIsNullThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		String userInfoResponse = "{\n"
				+ "   \"email\": \"full_name@provider.com\",\n"
				+ "   \"name\": \"full name\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userNameAttributeName(StandardClaimNames.EMAIL)
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService
				.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken)))
			.withMessageContaining("invalid_user_info_response");
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseAndUserInfoSubjectNotSameAsIdTokenSubjectThenThrowOAuth2AuthenticationException() {
		String userInfoResponse = "{\n" + "	\"sub\": \"other-subject\"\n" + "}\n";
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService
				.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken)))
			.withMessageContaining("invalid_user_info_response");
	}

	@Test
	public void loadUserWhenUserInfoSuccessResponseInvalidThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"sub\": \"subject1\",\n"
			+ "   \"name\": \"first last\",\n"
			+ "   \"given_name\": \"first\",\n"
			+ "   \"family_name\": \"last\",\n"
			+ "   \"preferred_username\": \"user1\",\n"
			+ "   \"email\": \"user1@example.com\"\n";
			// "}\n"; // Make the JSON invalid/malformed
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService
				.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource");
	}

	@Test
	public void loadUserWhenServerErrorThenThrowOAuth2AuthenticationException() {
		this.server.enqueue(new MockResponse().setResponseCode(500));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService
				.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource: 500 Server Error");
	}

	@Test
	public void loadUserWhenUserInfoUriInvalidThenThrowOAuth2AuthenticationException() {
		String userInfoUri = "https://invalid-provider.com/user";
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService
				.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken)))
			.withMessageContaining(
					"[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource");
	}

	@Test
	public void loadUserWhenCustomUserNameAttributeNameThenGetNameReturnsCustomUserName() {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"sub\": \"subject1\",\n"
			+ "   \"name\": \"first last\",\n"
			+ "   \"given_name\": \"first\",\n"
			+ "   \"family_name\": \"last\",\n"
			+ "   \"preferred_username\": \"user1\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userNameAttributeName(StandardClaimNames.EMAIL)
			.build();
		OidcUser user = this.userService
			.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken));
		assertThat(user.getName()).isEqualTo("user1@example.com");
	}

	// gh-5294
	@Test
	public void loadUserWhenUserInfoSuccessResponseThenAcceptHeaderJson() throws Exception {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"sub\": \"subject1\",\n"
			+ "   \"name\": \"first last\",\n"
			+ "   \"given_name\": \"first\",\n"
			+ "   \"family_name\": \"last\",\n"
			+ "   \"preferred_username\": \"user1\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		this.userService.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken));
		assertThat(this.server.takeRequest(1, TimeUnit.SECONDS).getHeader(HttpHeaders.ACCEPT))
			.isEqualTo(MediaType.APPLICATION_JSON_VALUE);
	}

	// gh-5500
	@Test
	public void loadUserWhenAuthenticationMethodHeaderSuccessResponseThenHttpMethodGet() throws Exception {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"sub\": \"subject1\",\n"
			+ "   \"name\": \"first last\",\n"
			+ "   \"given_name\": \"first\",\n"
			+ "   \"family_name\": \"last\",\n"
			+ "   \"preferred_username\": \"user1\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		this.userService.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken));
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
			+ "   \"sub\": \"subject1\",\n"
			+ "   \"name\": \"first last\",\n"
			+ "   \"given_name\": \"first\",\n"
			+ "   \"family_name\": \"last\",\n"
			+ "   \"preferred_username\": \"user1\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.build();
		this.userService.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken));
		RecordedRequest request = this.server.takeRequest();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.POST.name());
		assertThat(request.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(request.getHeader(HttpHeaders.CONTENT_TYPE)).contains(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		assertThat(request.getBody().readUtf8()).isEqualTo("access_token=" + this.accessToken.getTokenValue());
	}

	@Test
	public void loadUserWhenCustomClaimTypeConverterFactorySetThenApplied() {
		// @formatter:off
		String userInfoResponse = "{\n"
			+ "   \"sub\": \"subject1\",\n"
			+ "   \"name\": \"first last\",\n"
			+ "   \"given_name\": \"first\",\n"
			+ "   \"family_name\": \"last\",\n"
			+ "   \"preferred_username\": \"user1\",\n"
			+ "   \"email\": \"user1@example.com\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> customClaimTypeConverterFactory = mock(
				Function.class);
		this.userService.setClaimTypeConverterFactory(customClaimTypeConverterFactory);
		given(customClaimTypeConverterFactory.apply(same(clientRegistration)))
			.willReturn(new ClaimTypeConverter(OidcUserService.createDefaultClaimTypeConverters()));
		this.userService.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken));
		verify(customClaimTypeConverterFactory).apply(same(clientRegistration));
	}

	@Test
	public void loadUserWhenTokenContainsScopesThenIndividualScopeAuthorities() {
		OidcUserService userService = new OidcUserService();
		userService.setRetrieveUserInfo((req) -> false);
		OidcUserRequest request = new OidcUserRequest(TestClientRegistrations.clientRegistration().build(),
				TestOAuth2AccessTokens.scopes("message:read", "message:write"), TestOidcIdTokens.idToken().build());
		OidcUser user = userService.loadUser(request);
		assertThat(user.getAuthorities()).hasSize(3);
		Iterator<? extends GrantedAuthority> authorities = user.getAuthorities().iterator();
		assertThat(authorities.next()).isInstanceOf(OidcUserAuthority.class);
		assertThat(authorities.next()).isEqualTo(new SimpleGrantedAuthority("SCOPE_message:read"));
		assertThat(authorities.next()).isEqualTo(new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void loadUserWhenTokenDoesNotContainScopesThenNoScopeAuthorities() {
		OidcUserService userService = new OidcUserService();
		OidcUserRequest request = new OidcUserRequest(this.clientRegistrationBuilder.build(),
				TestOAuth2AccessTokens.noScopes(), this.idToken);
		OidcUser user = userService.loadUser(request);
		assertThat(user.getAuthorities()).hasSize(1);
		Iterator<? extends GrantedAuthority> authorities = user.getAuthorities().iterator();
		assertThat(authorities.next()).isInstanceOf(OidcUserAuthority.class);
	}

	@Test
	public void loadUserWhenTokenDoesNotContainScopesAndUserInfoUriThenUserInfoRequested() {
		// @formatter:off
		String userInfoResponse = "{\n"
				+ "   \"sub\": \"subject1\",\n"
				+ "   \"name\": \"first last\",\n"
				+ "   \"given_name\": \"first\",\n"
				+ "   \"family_name\": \"last\",\n"
				+ "   \"preferred_username\": \"user1\",\n"
				+ "   \"email\": \"user1@example.com\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(userInfoResponse));
		String userInfoUri = this.server.url("/user").toString();
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.userInfoUri(userInfoUri).build();
		OidcUserService userService = new OidcUserService();
		OidcUserRequest request = new OidcUserRequest(clientRegistration, TestOAuth2AccessTokens.noScopes(),
				this.idToken);
		OidcUser user = userService.loadUser(request);
		assertThat(user.getUserInfo()).isNotNull();
	}

	@Test
	public void loadUserWhenNestedUserInfoSuccessThenReturnUser() {
		// @formatter:off
		String userInfoResponse = "{\n"
				+ "   \"user\": {\"user-name\": \"user1\"},\n"
				+ "   \"sub\" : \"subject1\",\n"
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
		OidcUserService userService = new OidcUserService();
		DefaultOAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
		oAuth2UserService.setAttributesConverter((request) -> (attributes) -> {
			Map<String, Object> user = (Map<String, Object>) attributes.get("user");
			attributes.put("user-name", user.get("user-name"));
			return attributes;
		});
		userService.setOauth2UserService(oAuth2UserService);
		OAuth2User user = userService.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken));
		assertThat(user.getName()).isEqualTo("user1");
		assertThat(user.getAttributes()).hasSize(9);
		assertThat(((Map<?, ?>) user.getAttribute("user")).get("user-name")).isEqualTo("user1");
		assertThat((String) user.getAttribute("first-name")).isEqualTo("first");
		assertThat((String) user.getAttribute("last-name")).isEqualTo("last");
		assertThat((String) user.getAttribute("middle-name")).isEqualTo("middle");
		assertThat((String) user.getAttribute("address")).isEqualTo("address");
		assertThat((String) user.getAttribute("email")).isEqualTo("user1@example.com");
		assertThat(user.getAuthorities()).hasSize(3);
		assertThat(user.getAuthorities().iterator().next()).isInstanceOf(OAuth2UserAuthority.class);
		OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) user.getAuthorities().iterator().next();
		assertThat(userAuthority.getAuthority()).isEqualTo("OIDC_USER");
		assertThat(userAuthority.getAttributes()).isEqualTo(user.getAttributes());
		assertThat(userAuthority.getUserNameAttributeName()).isEqualTo("user-name");
	}

	private MockResponse jsonResponse(String json) {
		// @formatter:off
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
		// @formatter:on
	}

}
