/*
 * Copyright 2002-2018 the original author or authors.
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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link JwtAuthenticationProvider}
 *
 * @author Josh Cummings
 */
@RunWith(MockitoJUnitRunner.class)
public class JwtAuthenticationProviderTests {
	@Mock
	JwtDecoder jwtDecoder;

	JwtAuthenticationProvider provider;

	@Before
	public void setup() {
		this.provider =
				new JwtAuthenticationProvider(this.jwtDecoder);
	}

	@Test
	public void authenticateWhenJwtDecodesThenAuthenticationHasAttributesContainedInJwt() {
		BearerTokenAuthenticationToken token = this.authentication();

		Map<String, Object> claims = new HashMap<>();
		claims.put("name", "value");
		Jwt jwt = this.jwt(claims);

		when(this.jwtDecoder.decode("token")).thenReturn(jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		assertThat(authentication.getTokenAttributes()).isEqualTo(claims);
	}

	@Test
	public void authenticateWhenJwtDecodeFailsThenRespondsWithInvalidToken() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwtDecoder.decode("token")).thenThrow(JwtException.class);

		assertThatCode(() -> this.provider.authenticate(token))
				.matches(failed -> failed instanceof OAuth2AuthenticationException)
				.matches(errorCode(BearerTokenErrorCodes.INVALID_TOKEN));
	}

	@Test
	public void authenticateWhenTokenHasScopeAttributeThenTranslatedToAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		Jwt jwt = this.jwt(Maps.newHashMap("scope", "message:read message:write"));

		when(this.jwtDecoder.decode(token.getToken())).thenReturn(jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(
				new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void authenticateWhenTokenHasEmptyScopeAttributeThenTranslatedToNoAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		Jwt jwt = this.jwt(Maps.newHashMap("scope", ""));

		when(this.jwtDecoder.decode(token.getToken())).thenReturn(jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly();
	}

	@Test
	public void authenticateWhenTokenHasScpAttributeThenTranslatedToAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		Jwt jwt = this.jwt(Maps.newHashMap("scp", Arrays.asList("message:read", "message:write")));

		when(this.jwtDecoder.decode(token.getToken())).thenReturn(jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(
				new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void authenticateWhenTokenHasEmptyScpAttributeThenTranslatedToNoAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		Jwt jwt = this.jwt(Maps.newHashMap("scp", Arrays.asList()));

		when(this.jwtDecoder.decode(token.getToken())).thenReturn(jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly();
	}

	@Test
	public void authenticateWhenTokenHasBothScopeAndScpThenScopeAttributeIsTranslatedToAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		Map<String, Object> claims = Maps.newHashMap("scp", Arrays.asList("message:read", "message:write"));
		claims.put("scope", "missive:read missive:write");
		Jwt jwt = this.jwt(claims);

		when(this.jwtDecoder.decode(token.getToken())).thenReturn(jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(
				new SimpleGrantedAuthority("SCOPE_missive:read"),
				new SimpleGrantedAuthority("SCOPE_missive:write"));
	}

	@Test
	public void authenticateWhenTokenHasEmptyScopeAndNonEmptyScpThenScopeAttributeIsTranslatedToNoAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		Map<String, Object> claims = Maps.newHashMap("scp", Arrays.asList("message:read", "message:write"));
		claims.put("scope", "");
		Jwt jwt = this.jwt(claims);

		when(this.jwtDecoder.decode(token.getToken())).thenReturn(jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly();
	}

	@Test
	public void authenticateWhenDecoderThrowsIncompatibleErrorMessageThenWrapsWithGenericOne() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwtDecoder.decode(token.getToken())).thenThrow(new JwtException("with \"invalid\" chars"));

		assertThatCode(() -> this.provider.authenticate(token))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.hasFieldOrPropertyWithValue(
						"error.description",
						"An error occurred while attempting to decode the Jwt: Invalid token");
	}

	@Test
	public void supportsWhenBearerTokenAuthenticationTokenThenReturnsTrue() {
		assertThat(this.provider.supports(BearerTokenAuthenticationToken.class)).isTrue();
	}

	private BearerTokenAuthenticationToken authentication() {
		return new BearerTokenAuthenticationToken("token");
	}

	private Jwt jwt(Map<String, Object> claims) {
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", JwsAlgorithms.RS256);

		return new Jwt("token", Instant.now(), Instant.now().plusSeconds(3600), headers, claims);
	}

	private Predicate<? super Throwable> errorCode(String errorCode) {
		return failed ->
				((OAuth2AuthenticationException) failed).getError().getErrorCode() == errorCode;
	}
}
