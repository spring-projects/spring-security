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
package org.springframework.security.oauth2.client.jackson2;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.DecimalUtils;
import org.junit.Before;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthenticationTokens;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.oidc.user.TestOidcUsers;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthenticationTokenMixin}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthenticationTokenMixinTests {

	private ObjectMapper mapper;

	@Before
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@Test
	public void serializeWhenMixinRegisteredThenSerializes() throws Exception {
		// OidcUser
		OAuth2AuthenticationToken authentication = TestOAuth2AuthenticationTokens.oidcAuthenticated();
		String expectedJson = asJson(authentication);
		String json = this.mapper.writeValueAsString(authentication);
		JSONAssert.assertEquals(expectedJson, json, true);

		// OAuth2User
		authentication = TestOAuth2AuthenticationTokens.authenticated();
		expectedJson = asJson(authentication);
		json = this.mapper.writeValueAsString(authentication);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	@Test
	public void serializeWhenRequiredAttributesOnlyThenSerializes() throws Exception {
		DefaultOidcUser principal = TestOidcUsers.create();
		principal = new DefaultOidcUser(principal.getAuthorities(), principal.getIdToken());
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(principal, Collections.emptyList(),
				"registration-id");
		String expectedJson = asJson(authentication);
		String json = this.mapper.writeValueAsString(authentication);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	@Test
	public void deserializeWhenMixinNotRegisteredThenThrowJsonProcessingException() {
		OAuth2AuthenticationToken authentication = TestOAuth2AuthenticationTokens.oidcAuthenticated();
		String json = asJson(authentication);
		assertThatThrownBy(() -> new ObjectMapper().readValue(json, OAuth2AuthenticationToken.class))
				.isInstanceOf(JsonProcessingException.class);
	}

	@Test
	public void deserializeWhenMixinRegisteredThenDeserializes() throws Exception {
		// OidcUser
		OAuth2AuthenticationToken expectedAuthentication = TestOAuth2AuthenticationTokens.oidcAuthenticated();
		String json = asJson(expectedAuthentication);
		OAuth2AuthenticationToken authentication = this.mapper.readValue(json, OAuth2AuthenticationToken.class);
		assertThat(authentication.getAuthorities()).containsExactlyElementsOf(expectedAuthentication.getAuthorities());
		assertThat(authentication.getDetails()).isEqualTo(expectedAuthentication.getDetails());
		assertThat(authentication.isAuthenticated()).isEqualTo(expectedAuthentication.isAuthenticated());
		assertThat(authentication.getAuthorizedClientRegistrationId())
				.isEqualTo(expectedAuthentication.getAuthorizedClientRegistrationId());
		DefaultOidcUser expectedOidcUser = (DefaultOidcUser) expectedAuthentication.getPrincipal();
		DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal();
		assertThat(oidcUser.getAuthorities().containsAll(expectedOidcUser.getAuthorities())).isTrue();
		assertThat(oidcUser.getAttributes()).containsExactlyEntriesOf(expectedOidcUser.getAttributes());
		assertThat(oidcUser.getName()).isEqualTo(expectedOidcUser.getName());
		OidcIdToken expectedIdToken = expectedOidcUser.getIdToken();
		OidcIdToken idToken = oidcUser.getIdToken();
		assertThat(idToken.getTokenValue()).isEqualTo(expectedIdToken.getTokenValue());
		assertThat(idToken.getIssuedAt()).isEqualTo(expectedIdToken.getIssuedAt());
		assertThat(idToken.getExpiresAt()).isEqualTo(expectedIdToken.getExpiresAt());
		assertThat(idToken.getClaims()).containsExactlyEntriesOf(expectedIdToken.getClaims());
		OidcUserInfo expectedUserInfo = expectedOidcUser.getUserInfo();
		OidcUserInfo userInfo = oidcUser.getUserInfo();
		assertThat(userInfo.getClaims()).containsExactlyEntriesOf(expectedUserInfo.getClaims());

		// OAuth2User
		expectedAuthentication = TestOAuth2AuthenticationTokens.authenticated();
		json = asJson(expectedAuthentication);
		authentication = this.mapper.readValue(json, OAuth2AuthenticationToken.class);
		assertThat(authentication.getAuthorities()).containsExactlyElementsOf(expectedAuthentication.getAuthorities());
		assertThat(authentication.getDetails()).isEqualTo(expectedAuthentication.getDetails());
		assertThat(authentication.isAuthenticated()).isEqualTo(expectedAuthentication.isAuthenticated());
		assertThat(authentication.getAuthorizedClientRegistrationId())
				.isEqualTo(expectedAuthentication.getAuthorizedClientRegistrationId());
		DefaultOAuth2User expectedOauth2User = (DefaultOAuth2User) expectedAuthentication.getPrincipal();
		DefaultOAuth2User oauth2User = (DefaultOAuth2User) authentication.getPrincipal();
		assertThat(oauth2User.getAuthorities().containsAll(expectedOauth2User.getAuthorities())).isTrue();
		assertThat(oauth2User.getAttributes()).containsExactlyEntriesOf(expectedOauth2User.getAttributes());
		assertThat(oauth2User.getName()).isEqualTo(expectedOauth2User.getName());
	}

	@Test
	public void deserializeWhenRequiredAttributesOnlyThenDeserializes() throws Exception {
		DefaultOidcUser expectedPrincipal = TestOidcUsers.create();
		expectedPrincipal = new DefaultOidcUser(expectedPrincipal.getAuthorities(), expectedPrincipal.getIdToken());
		OAuth2AuthenticationToken expectedAuthentication = new OAuth2AuthenticationToken(expectedPrincipal,
				Collections.emptyList(), "registration-id");
		String json = asJson(expectedAuthentication);
		OAuth2AuthenticationToken authentication = this.mapper.readValue(json, OAuth2AuthenticationToken.class);
		assertThat(authentication.getAuthorities()).isEmpty();
		assertThat(authentication.getDetails()).isEqualTo(expectedAuthentication.getDetails());
		assertThat(authentication.isAuthenticated()).isEqualTo(expectedAuthentication.isAuthenticated());
		assertThat(authentication.getAuthorizedClientRegistrationId())
				.isEqualTo(expectedAuthentication.getAuthorizedClientRegistrationId());
		DefaultOidcUser principal = (DefaultOidcUser) authentication.getPrincipal();
		assertThat(principal.getAuthorities().containsAll(expectedPrincipal.getAuthorities())).isTrue();
		assertThat(principal.getAttributes()).containsExactlyEntriesOf(expectedPrincipal.getAttributes());
		assertThat(principal.getName()).isEqualTo(expectedPrincipal.getName());
		OidcIdToken expectedIdToken = expectedPrincipal.getIdToken();
		OidcIdToken idToken = principal.getIdToken();
		assertThat(idToken.getTokenValue()).isEqualTo(expectedIdToken.getTokenValue());
		assertThat(idToken.getIssuedAt()).isEqualTo(expectedIdToken.getIssuedAt());
		assertThat(idToken.getExpiresAt()).isEqualTo(expectedIdToken.getExpiresAt());
		assertThat(idToken.getClaims()).containsExactlyEntriesOf(expectedIdToken.getClaims());
		assertThat(principal.getUserInfo()).isNull();
	}

	private static String asJson(OAuth2AuthenticationToken authentication) {
		String principalJson = authentication.getPrincipal() instanceof DefaultOidcUser
				? asJson((DefaultOidcUser) authentication.getPrincipal())
				: asJson((DefaultOAuth2User) authentication.getPrincipal());
		// @formatter:off
		return "{\n" +
				"  \"@class\": \"org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken\",\n" +
				"  \"principal\": " + principalJson + ",\n" +
				"  \"authorities\": " + asJson(authentication.getAuthorities(), "java.util.Collections$UnmodifiableRandomAccessList") + ",\n" +
				"  \"authorizedClientRegistrationId\": \"" + authentication.getAuthorizedClientRegistrationId() + "\",\n" +
				"  \"details\": null\n" +
				"}";
		// @formatter:on
	}

	private static String asJson(DefaultOAuth2User oauth2User) {
		// @formatter:off
		return "{\n" +
				"    \"@class\": \"org.springframework.security.oauth2.core.user.DefaultOAuth2User\",\n" +
				"    \"authorities\": " + asJson(oauth2User.getAuthorities(), "java.util.Collections$UnmodifiableSet") + ",\n" +
				"    \"attributes\": {\n" +
				"      \"@class\": \"java.util.Collections$UnmodifiableMap\",\n" +
				"      \"username\": \"user\"\n" +
				"    },\n" +
				"    \"nameAttributeKey\": \"username\"\n" +
				"  }";
		// @formatter:on
	}

	private static String asJson(DefaultOidcUser oidcUser) {
		// @formatter:off
		return "{\n" +
				"    \"@class\": \"org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser\",\n" +
				"    \"authorities\": " + asJson(oidcUser.getAuthorities(), "java.util.Collections$UnmodifiableSet") + ",\n" +
				"    \"idToken\": " + asJson(oidcUser.getIdToken()) + ",\n" +
				"    \"userInfo\": " + asJson(oidcUser.getUserInfo()) + ",\n" +
				"    \"nameAttributeKey\": \"" + IdTokenClaimNames.SUB + "\"\n" +
				"  }";
		// @formatter:on
	}

	private static String asJson(Collection<? extends GrantedAuthority> authorities, String classTypeInfo) {
		OAuth2UserAuthority oauth2UserAuthority = null;
		OidcUserAuthority oidcUserAuthority = null;
		List<SimpleGrantedAuthority> simpleAuthorities = new ArrayList<>();
		for (GrantedAuthority authority : authorities) {
			if (authority instanceof OidcUserAuthority) {
				oidcUserAuthority = (OidcUserAuthority) authority;
			}
			else if (authority instanceof OAuth2UserAuthority) {
				oauth2UserAuthority = (OAuth2UserAuthority) authority;
			}
			else if (authority instanceof SimpleGrantedAuthority) {
				simpleAuthorities.add((SimpleGrantedAuthority) authority);
			}
		}
		String authoritiesJson = oidcUserAuthority != null ? asJson(oidcUserAuthority)
				: oauth2UserAuthority != null ? asJson(oauth2UserAuthority) : "";
		if (!simpleAuthorities.isEmpty()) {
			if (!StringUtils.isEmpty(authoritiesJson)) {
				authoritiesJson += ",";
			}
			authoritiesJson += asJson(simpleAuthorities);
		}
		// @formatter:off
		return "[\n" +
				"      \"" + classTypeInfo + "\",\n" +
				"      [" + authoritiesJson + "]\n" +
				"    ]";
		// @formatter:on
	}

	private static String asJson(OAuth2UserAuthority oauth2UserAuthority) {
		// @formatter:off
		return "{\n" +
				"          \"@class\": \"org.springframework.security.oauth2.core.user.OAuth2UserAuthority\",\n" +
				"          \"authority\": \"" + oauth2UserAuthority.getAuthority() + "\",\n" +
				"          \"attributes\": {\n" +
				"            \"@class\": \"java.util.Collections$UnmodifiableMap\",\n" +
				"            \"username\": \"user\"\n" +
				"          }\n" +
				"        }";
		// @formatter:on
	}

	private static String asJson(OidcUserAuthority oidcUserAuthority) {
		// @formatter:off
		return "{\n" +
				"          \"@class\": \"org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority\",\n" +
				"          \"authority\": \"" + oidcUserAuthority.getAuthority() + "\",\n" +
				"          \"idToken\": " + asJson(oidcUserAuthority.getIdToken()) + ",\n" +
				"          \"userInfo\": " + asJson(oidcUserAuthority.getUserInfo()) + "\n" +
				"        }";
		// @formatter:on
	}

	private static String asJson(List<SimpleGrantedAuthority> simpleAuthorities) {
		// @formatter:off
		return simpleAuthorities.stream()
				.map(authority -> "{\n" +
						"        \"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\",\n" +
						"        \"authority\": \"" + authority.getAuthority() + "\"\n" +
						"      }")
				.collect(Collectors.joining(","));
		// @formatter:on
	}

	private static String asJson(OidcIdToken idToken) {
		String aud = "";
		if (!CollectionUtils.isEmpty(idToken.getAudience())) {
			aud = StringUtils.collectionToDelimitedString(idToken.getAudience(), ",", "\"", "\"");
		}
		// @formatter:off
		return "{\n" +
				"      \"@class\": \"org.springframework.security.oauth2.core.oidc.OidcIdToken\",\n" +
				"      \"tokenValue\": \"" + idToken.getTokenValue() + "\",\n" +
				"      \"issuedAt\": " + toString(idToken.getIssuedAt()) + ",\n" +
				"      \"expiresAt\": " + toString(idToken.getExpiresAt()) + ",\n" +
				"      \"claims\": {\n" +
				"        \"@class\": \"java.util.Collections$UnmodifiableMap\",\n" +
				"        \"iat\": [\n" +
				"          \"java.time.Instant\",\n" +
				"          " + toString(idToken.getIssuedAt()) + "\n" +
				"        ],\n" +
				"        \"exp\": [\n" +
				"          \"java.time.Instant\",\n" +
				"          " + toString(idToken.getExpiresAt()) + "\n" +
				"        ],\n" +
				"        \"sub\": \"" + idToken.getSubject() + "\",\n" +
				"        \"iss\": \"" + idToken.getIssuer() + "\",\n" +
				"        \"aud\": [\n" +
				"          \"java.util.Collections$UnmodifiableSet\",\n" +
				"          [" + aud + "]\n" +
				"        ],\n" +
				"        \"azp\": \"" + idToken.getAuthorizedParty() + "\"\n" +
				"      }\n" +
				"    }";
		// @formatter:on
	}

	private static String asJson(OidcUserInfo userInfo) {
		if (userInfo == null) {
			return null;
		}
		// @formatter:off
		return "{\n" +
				"      \"@class\": \"org.springframework.security.oauth2.core.oidc.OidcUserInfo\",\n" +
				"      \"claims\": {\n" +
				"        \"@class\": \"java.util.Collections$UnmodifiableMap\",\n" +
				"        \"sub\": \"" + userInfo.getSubject() + "\",\n" +
				"        \"name\": \"" + userInfo.getClaim(StandardClaimNames.NAME) + "\"\n" +
				"      }\n" +
				"    }";
		// @formatter:on
	}

	private static String toString(Instant instant) {
		if (instant == null) {
			return null;
		}
		return DecimalUtils.toBigDecimal(instant.getEpochSecond(), instant.getNano()).toString();
	}

}
