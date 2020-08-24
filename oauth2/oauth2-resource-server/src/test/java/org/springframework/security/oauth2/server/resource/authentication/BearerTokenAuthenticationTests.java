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

package org.springframework.security.oauth2.server.resource.authentication;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.minidev.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link BearerTokenAuthentication}
 *
 * @author Josh Cummings
 */
public class BearerTokenAuthenticationTests {

	private final OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
			Instant.now(), Instant.now().plusSeconds(3600));

	private final String name = "sub";

	private Map<String, Object> attributesMap = new HashMap<>();

	private DefaultOAuth2AuthenticatedPrincipal principal;

	private final Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("USER");

	@Before
	public void setUp() {
		this.attributesMap.put(OAuth2IntrospectionClaimNames.SUBJECT, this.name);
		this.attributesMap.put(OAuth2IntrospectionClaimNames.CLIENT_ID, "client_id");
		this.attributesMap.put(OAuth2IntrospectionClaimNames.USERNAME, "username");
		this.principal = new DefaultOAuth2AuthenticatedPrincipal(this.attributesMap, null);
	}

	@Test
	public void getNameWhenConfiguredInConstructorThenReturnsName() {
		OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(this.name, this.attributesMap,
				this.authorities);
		BearerTokenAuthentication authenticated = new BearerTokenAuthentication(principal, this.token,
				this.authorities);
		assertThat(authenticated.getName()).isEqualTo(this.name);
	}

	@Test
	public void getNameWhenHasNoSubjectThenReturnsNull() {
		OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(
				Collections.singletonMap("claim", "value"), null);
		BearerTokenAuthentication authenticated = new BearerTokenAuthentication(principal, this.token, null);
		assertThat(authenticated.getName()).isNull();
	}

	@Test
	public void getNameWhenTokenHasUsernameThenReturnsUsernameAttribute() {
		BearerTokenAuthentication authenticated = new BearerTokenAuthentication(this.principal, this.token, null);
		// @formatter:off
		assertThat(authenticated.getName())
				.isEqualTo(this.principal.getAttribute(OAuth2IntrospectionClaimNames.SUBJECT));
		// @formatter:on
	}

	@Test
	public void constructorWhenTokenIsNullThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new BearerTokenAuthentication(this.principal, null, null))
				.withMessageContaining("token cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenCredentialIsNullThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new BearerTokenAuthentication(null, this.token, null))
				.withMessageContaining("principal cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenPassingAllAttributesThenTokenIsAuthenticated() {
		OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal("harris",
				Collections.singletonMap("claim", "value"), null);
		BearerTokenAuthentication authenticated = new BearerTokenAuthentication(principal, this.token, null);
		assertThat(authenticated.isAuthenticated()).isTrue();
	}

	@Test
	public void getTokenAttributesWhenHasTokenThenReturnsThem() {
		BearerTokenAuthentication authenticated = new BearerTokenAuthentication(this.principal, this.token,
				Collections.emptyList());
		assertThat(authenticated.getTokenAttributes()).isEqualTo(this.principal.getAttributes());
	}

	@Test
	public void getAuthoritiesWhenHasAuthoritiesThenReturnsThem() {
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("USER");
		BearerTokenAuthentication authenticated = new BearerTokenAuthentication(this.principal, this.token,
				authorities);
		assertThat(authenticated.getAuthorities()).isEqualTo(authorities);
	}

	// gh-6843
	@Test
	public void constructorWhenDefaultParametersThenSetsPrincipalToAttributesCopy() {
		JSONObject attributes = new JSONObject();
		attributes.put("active", true);
		OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(attributes, null);
		BearerTokenAuthentication token = new BearerTokenAuthentication(principal, this.token, null);
		assertThat(token.getPrincipal()).isNotSameAs(attributes);
		assertThat(token.getTokenAttributes()).isNotSameAs(attributes);
	}

	// gh-6843
	@Test
	public void toStringWhenAttributesContainsURLThenDoesNotFail() throws Exception {
		JSONObject attributes = new JSONObject(Collections.singletonMap("iss", new URL("https://idp.example.com")));
		OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(attributes, null);
		BearerTokenAuthentication token = new BearerTokenAuthentication(principal, this.token, null);
		token.toString();
	}

}
