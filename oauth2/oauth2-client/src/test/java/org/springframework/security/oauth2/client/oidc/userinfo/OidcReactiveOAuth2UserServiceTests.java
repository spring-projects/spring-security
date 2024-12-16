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

package org.springframework.security.oauth2.client.oidc.userinfo;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.1
 */
@ExtendWith(MockitoExtension.class)
public class OidcReactiveOAuth2UserServiceTests {

	@Mock
	private ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;

	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration()
		.userNameAttributeName(IdTokenClaimNames.SUB);

	private OidcIdToken idToken = TestOidcIdTokens.idToken().build();

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
			Instant.now(), Instant.now().plus(Duration.ofDays(1)), Collections.singleton("read:user"));

	private OidcReactiveOAuth2UserService userService = new OidcReactiveOAuth2UserService();

	@BeforeEach
	public void setup() {
		this.userService.setOauth2UserService(this.oauth2UserService);
	}

	@Test
	public void createDefaultClaimTypeConvertersWhenCalledThenDefaultsAreCorrect() {
		Map<String, Converter<Object, ?>> claimTypeConverters = OidcReactiveOAuth2UserService
			.createDefaultClaimTypeConverters();
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.EMAIL_VERIFIED);
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.PHONE_NUMBER_VERIFIED);
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.UPDATED_AT);
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
	public void loadUserWhenUserInfoUriNullThenUserInfoNotRetrieved() {
		this.registration.userInfoUri(null);
		OidcUser user = this.userService.loadUser(userRequest()).block();
		assertThat(user.getUserInfo()).isNull();
	}

	@Test
	public void loadUserWhenOAuth2UserEmptyThenNullUserInfo() {
		given(this.oauth2UserService.loadUser(any())).willReturn(Mono.empty());
		OidcUser user = this.userService.loadUser(userRequest()).block();
		assertThat(user.getUserInfo()).isNull();
	}

	@Test
	public void loadUserWhenOAuth2UserSubjectNullThenOAuth2AuthenticationException() {
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"),
				Collections.singletonMap("user", "rob"), "user");
		given(this.oauth2UserService.loadUser(any())).willReturn(Mono.just(oauth2User));
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(userRequest()).block());
	}

	@Test
	public void loadUserWhenOAuth2UserSubjectNotEqualThenOAuth2AuthenticationException() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(StandardClaimNames.SUB, "not-equal");
		attributes.put("user", "rob");
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"), attributes,
				"user");
		given(this.oauth2UserService.loadUser(any())).willReturn(Mono.just(oauth2User));
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.userService.loadUser(userRequest()).block());
	}

	@Test
	public void loadUserWhenOAuth2UserThenUserInfoNotNull() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(StandardClaimNames.SUB, "subject");
		attributes.put("user", "rob");
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"), attributes,
				"user");
		given(this.oauth2UserService.loadUser(any())).willReturn(Mono.just(oauth2User));
		assertThat(this.userService.loadUser(userRequest()).block().getUserInfo()).isNotNull();
	}

	@Test
	public void loadUserWhenOAuth2UserAndUser() {
		this.registration.userNameAttributeName("user");
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(StandardClaimNames.SUB, "subject");
		attributes.put("user", "rob");
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"), attributes,
				"user");
		given(this.oauth2UserService.loadUser(any())).willReturn(Mono.just(oauth2User));
		assertThat(this.userService.loadUser(userRequest()).block().getName()).isEqualTo("rob");
	}

	@Test
	public void loadUserWhenCustomClaimTypeConverterFactorySetThenApplied() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(StandardClaimNames.SUB, "subject");
		attributes.put("user", "rob");
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"), attributes,
				"user");
		given(this.oauth2UserService.loadUser(any())).willReturn(Mono.just(oauth2User));
		OidcUserRequest userRequest = userRequest();
		Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> customClaimTypeConverterFactory = mock(
				Function.class);
		this.userService.setClaimTypeConverterFactory(customClaimTypeConverterFactory);
		given(customClaimTypeConverterFactory.apply(same(userRequest.getClientRegistration())))
			.willReturn(new ClaimTypeConverter(OidcReactiveOAuth2UserService.createDefaultClaimTypeConverters()));
		this.userService.loadUser(userRequest).block().getUserInfo();
		verify(customClaimTypeConverterFactory).apply(same(userRequest.getClientRegistration()));
	}

	@Test
	public void loadUserWhenTokenScopesIsEmptyThenUserInfoNotRetrieved() {
		// @formatter:off
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				this.accessToken.getIssuedAt(),
				this.accessToken.getExpiresAt(),
				Collections.emptySet());
		// @formatter:on
		OidcUserRequest userRequest = new OidcUserRequest(this.registration.build(), accessToken, this.idToken);
		OidcUser oidcUser = this.userService.loadUser(userRequest).block();
		assertThat(oidcUser).isNotNull();
		assertThat(oidcUser.getUserInfo()).isNull();
	}

	@Test
	public void loadUserWhenCustomRetrieveUserInfoSetThenUsed() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(StandardClaimNames.SUB, "subject");
		attributes.put("user", "steve");
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"), attributes,
				"user");
		given(this.oauth2UserService.loadUser(any())).willReturn(Mono.just(oauth2User));
		Predicate<OidcUserRequest> customRetrieveUserInfo = mock(Predicate.class);
		this.userService.setRetrieveUserInfo(customRetrieveUserInfo);
		given(customRetrieveUserInfo.test(any(OidcUserRequest.class))).willReturn(true);
		// @formatter:off
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				this.accessToken.getIssuedAt(),
				this.accessToken.getExpiresAt(),
				Collections.emptySet());
		// @formatter:on
		OidcUserRequest userRequest = new OidcUserRequest(this.registration.build(), accessToken, this.idToken);
		OidcUser oidcUser = this.userService.loadUser(userRequest).block();
		assertThat(oidcUser).isNotNull();
		assertThat(oidcUser.getUserInfo()).isNotNull();
		verify(customRetrieveUserInfo).test(userRequest);
	}

	@Test
	public void loadUserWhenCustomOidcUserMapperSetThenUsed() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(StandardClaimNames.SUB, "subject");
		attributes.put("user", "steve");
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"), attributes,
				"user");
		given(this.oauth2UserService.loadUser(any(OidcUserRequest.class))).willReturn(Mono.just(oauth2User));
		BiFunction<OidcUserRequest, OidcUserInfo, Mono<OidcUser>> customOidcUserMapper = mock(BiFunction.class);
		OidcUser actualUser = new DefaultOidcUser(AuthorityUtils.createAuthorityList("a", "b"), this.idToken,
				IdTokenClaimNames.SUB);
		given(customOidcUserMapper.apply(any(OidcUserRequest.class), any(OidcUserInfo.class)))
			.willReturn(Mono.just(actualUser));
		this.userService.setOidcUserMapper(customOidcUserMapper);
		OidcUserRequest userRequest = userRequest();
		OidcUser oidcUser = this.userService.loadUser(userRequest).block();
		assertThat(oidcUser).isNotNull();
		assertThat(oidcUser).isEqualTo(actualUser);
		ArgumentCaptor<OidcUserInfo> userInfoCaptor = ArgumentCaptor.forClass(OidcUserInfo.class);
		verify(customOidcUserMapper).apply(eq(userRequest), userInfoCaptor.capture());
		OidcUserInfo userInfo = userInfoCaptor.getValue();
		assertThat(userInfo.getSubject()).isEqualTo("subject");
		assertThat(userInfo.getClaimAsString("user")).isEqualTo("steve");
	}

	@Test
	public void loadUserWhenCustomOidcUserMapperSetAndUserInfoNotRetrievedThenUsed() {
		// @formatter:off
		this.accessToken = new OAuth2AccessToken(
				this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				this.accessToken.getIssuedAt(),
				this.accessToken.getExpiresAt(),
				Collections.emptySet());
		// @formatter:on
		BiFunction<OidcUserRequest, OidcUserInfo, Mono<OidcUser>> customOidcUserMapper = mock(BiFunction.class);
		OidcUser actualUser = new DefaultOidcUser(AuthorityUtils.createAuthorityList("a", "b"), this.idToken,
				IdTokenClaimNames.SUB);
		given(customOidcUserMapper.apply(any(OidcUserRequest.class), isNull())).willReturn(Mono.just(actualUser));
		this.userService.setOidcUserMapper(customOidcUserMapper);
		OidcUserRequest userRequest = userRequest();
		OidcUser oidcUser = this.userService.loadUser(userRequest).block();
		assertThat(oidcUser).isNotNull();
		assertThat(oidcUser).isEqualTo(actualUser);
		verify(customOidcUserMapper).apply(eq(userRequest), isNull(OidcUserInfo.class));
	}

	@Test
	public void loadUserWhenTokenContainsScopesThenIndividualScopeAuthorities() {
		OidcReactiveOAuth2UserService userService = new OidcReactiveOAuth2UserService();
		OidcUserRequest request = new OidcUserRequest(TestClientRegistrations.clientRegistration().build(),
				TestOAuth2AccessTokens.scopes("message:read", "message:write"), TestOidcIdTokens.idToken().build());
		OidcUser user = userService.loadUser(request).block();
		assertThat(user.getAuthorities()).hasSize(3);
		Iterator<? extends GrantedAuthority> authorities = user.getAuthorities().iterator();
		assertThat(authorities.next()).isInstanceOf(OAuth2UserAuthority.class);
		assertThat(authorities.next()).isEqualTo(new SimpleGrantedAuthority("SCOPE_message:read"));
		assertThat(authorities.next()).isEqualTo(new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void loadUserWhenTokenDoesNotContainScopesThenNoScopeAuthorities() {
		OidcReactiveOAuth2UserService userService = new OidcReactiveOAuth2UserService();
		OidcUserRequest request = new OidcUserRequest(TestClientRegistrations.clientRegistration().build(),
				TestOAuth2AccessTokens.noScopes(), TestOidcIdTokens.idToken().build());
		OidcUser user = userService.loadUser(request).block();
		assertThat(user.getAuthorities()).hasSize(1);
		Iterator<? extends GrantedAuthority> authorities = user.getAuthorities().iterator();
		assertThat(authorities.next()).isInstanceOf(OAuth2UserAuthority.class);
		OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) user.getAuthorities().iterator().next();
		assertThat(userAuthority.getAuthority()).isEqualTo("OIDC_USER");
		assertThat(userAuthority.getAttributes()).isEqualTo(user.getAttributes());
		assertThat(userAuthority.getUserNameAttributeName()).isEqualTo("id");
	}

	@Test
	public void loadUserWhenNestedUserInfoSuccessThenReturnUser() throws IOException {
		// @formatter:off
		String userInfoResponse = "{\n"
				+ "   \"user\": {\"user-name\": \"user1\"},\n"
				+ "   \"sub\" : \"" + this.idToken.getSubject() + "\",\n"
				+ "   \"first-name\": \"first\",\n"
				+ "   \"last-name\": \"last\",\n"
				+ "   \"middle-name\": \"middle\",\n"
				+ "   \"address\": \"address\",\n"
				+ "   \"email\": \"user1@example.com\"\n"
				+ "}\n";
		// @formatter:on
		try (MockWebServer server = new MockWebServer()) {
			server.start();
			enqueueApplicationJsonBody(server, userInfoResponse);
			String userInfoUri = server.url("/user").toString();
			ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.userInfoUri(userInfoUri)
				.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
				.userNameAttributeName("user-name")
				.build();
			OidcReactiveOAuth2UserService userService = new OidcReactiveOAuth2UserService();
			DefaultReactiveOAuth2UserService oAuth2UserService = new DefaultReactiveOAuth2UserService();
			oAuth2UserService.setAttributesConverter((request) -> (attributes) -> {
				Map<String, Object> user = (Map<String, Object>) attributes.get("user");
				attributes.put("user-name", user.get("user-name"));
				return attributes;
			});
			userService.setOauth2UserService(oAuth2UserService);
			OAuth2User user = userService
				.loadUser(new OidcUserRequest(clientRegistration, this.accessToken, this.idToken))
				.block();
			assertThat(user.getName()).isEqualTo("user1");
			assertThat(user.getAttributes()).hasSize(13);
			assertThat(((Map<?, ?>) user.getAttribute("user")).get("user-name")).isEqualTo("user1");
			assertThat((String) user.getAttribute("first-name")).isEqualTo("first");
			assertThat((String) user.getAttribute("last-name")).isEqualTo("last");
			assertThat((String) user.getAttribute("middle-name")).isEqualTo("middle");
			assertThat((String) user.getAttribute("address")).isEqualTo("address");
			assertThat((String) user.getAttribute("email")).isEqualTo("user1@example.com");
			assertThat(user.getAuthorities()).hasSize(2);
			assertThat(user.getAuthorities().iterator().next()).isInstanceOf(OAuth2UserAuthority.class);
			OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) user.getAuthorities().iterator().next();
			assertThat(userAuthority.getAuthority()).isEqualTo("OIDC_USER");
			assertThat(userAuthority.getAttributes()).isEqualTo(user.getAttributes());
			assertThat(userAuthority.getUserNameAttributeName()).isEqualTo("user-name");
		}
	}

	private OidcUserRequest userRequest() {
		return new OidcUserRequest(this.registration.build(), this.accessToken, this.idToken);
	}

	private void enqueueApplicationJsonBody(MockWebServer server, String json) {
		server.enqueue(
				new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json));
	}

}
