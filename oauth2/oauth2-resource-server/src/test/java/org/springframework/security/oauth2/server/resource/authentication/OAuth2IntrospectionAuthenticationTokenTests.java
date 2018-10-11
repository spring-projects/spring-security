/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource.authentication;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.SUBJECT;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.USERNAME;

/**
 * Tests for {@link OAuth2IntrospectionAuthenticationToken}
 *
 * @author Josh Cummings
 */
public class OAuth2IntrospectionAuthenticationTokenTests {
	private final OAuth2AccessToken token =
			new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"token", Instant.now(), Instant.now().plusSeconds(3600));
	private final Map<String, Object> attributes = new HashMap<>();
	private final String name = "sub";

	@Before
	public void setUp() {
		this.attributes.put(SUBJECT, this.name);
		this.attributes.put(CLIENT_ID, "client_id");
		this.attributes.put(USERNAME, "username");
	}

	@Test
	public void getNameWhenConfiguredInConstructorThenReturnsName() {
		OAuth2IntrospectionAuthenticationToken authenticated =
				new OAuth2IntrospectionAuthenticationToken(this.token, this.attributes,
						AuthorityUtils.createAuthorityList("USER"), this.name);
		assertThat(authenticated.getName()).isEqualTo(this.name);
	}

	@Test
	public void getNameWhenHasNoSubjectThenReturnsNull() {
		OAuth2IntrospectionAuthenticationToken authenticated =
				new OAuth2IntrospectionAuthenticationToken(this.token, Collections.singletonMap("claim", "value"),
						Collections.emptyList());
		assertThat(authenticated.getName()).isNull();
	}

	@Test
	public void getNameWhenTokenHasUsernameThenReturnsUsernameAttribute() {
		OAuth2IntrospectionAuthenticationToken authenticated =
				new OAuth2IntrospectionAuthenticationToken(this.token, this.attributes, Collections.emptyList());
		assertThat(authenticated.getName()).isEqualTo(this.attributes.get(SUBJECT));
	}

	@Test
	public void constructorWhenTokenIsNullThenThrowsException() {
		assertThatCode(() -> new OAuth2IntrospectionAuthenticationToken(null, null, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("token cannot be null");
	}

	@Test
	public void constructorWhenAttributesAreNullOrEmptyThenThrowsException() {
		assertThatCode(() -> new OAuth2IntrospectionAuthenticationToken(this.token, null, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("principal cannot be null");

		assertThatCode(() -> new OAuth2IntrospectionAuthenticationToken(this.token, Collections.emptyMap(), null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("attributes cannot be empty");
	}

	@Test
	public void constructorWhenPassingAllAttributesThenTokenIsAuthenticated() {
		OAuth2IntrospectionAuthenticationToken authenticated =
				new OAuth2IntrospectionAuthenticationToken(this.token, Collections.singletonMap("claim", "value"),
						Collections.emptyList(), "harris");
		assertThat(authenticated.isAuthenticated()).isTrue();
	}

	@Test
	public void getTokenAttributesWhenHasTokenThenReturnsThem() {
		OAuth2IntrospectionAuthenticationToken authenticated =
				new OAuth2IntrospectionAuthenticationToken(this.token, this.attributes, Collections.emptyList());
		assertThat(authenticated.getTokenAttributes()).isEqualTo(this.attributes);
	}

	@Test
	public void getAuthoritiesWhenHasAuthoritiesThenReturnsThem() {
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("USER");
		OAuth2IntrospectionAuthenticationToken authenticated =
				new OAuth2IntrospectionAuthenticationToken(this.token, this.attributes, authorities);
		assertThat(authenticated.getAuthorities()).isEqualTo(authorities);
	}
}
