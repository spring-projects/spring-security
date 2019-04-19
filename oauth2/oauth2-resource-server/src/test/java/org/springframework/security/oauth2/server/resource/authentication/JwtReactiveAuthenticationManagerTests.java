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

package org.springframework.security.oauth2.server.resource.authentication;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class JwtReactiveAuthenticationManagerTests {
	@Mock
	private ReactiveJwtDecoder jwtDecoder;

	private JwtReactiveAuthenticationManager manager;

	private Jwt jwt;

	@Before
	public void setup() {
		this.manager = new JwtReactiveAuthenticationManager(this.jwtDecoder);

		Map<String, Object> claims = new HashMap<>();
		claims.put("scope", "message:read message:write");
		claims.put(JwtClaimNames.IAT, Instant.now());
		claims.put(JwtClaimNames.EXP, Instant.now().plusSeconds(3600));

		this.jwt = new Jwt("jwt", claims, claims);
	}

	@Test
	public void constructorWhenJwtDecoderNullThenIllegalArgumentException() {
		this.jwtDecoder = null;
		assertThatCode(() -> new JwtReactiveAuthenticationManager(this.jwtDecoder))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void authenticateWhenWrongTypeThenEmpty() {
		TestingAuthenticationToken token = new TestingAuthenticationToken("foo", "bar");

		assertThat(this.manager.authenticate(token).block()).isNull();
	}

	@Test
	public void authenticateWhenEmptyJwtThenEmpty() {
		BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken("token-1");
		when(this.jwtDecoder.decode(token.getToken())).thenReturn(Mono.empty());

		assertThat(this.manager.authenticate(token).block()).isNull();
	}

	@Test
	public void authenticateWhenJwtExceptionThenOAuth2AuthenticationException() {
		BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken("token-1");
		when(this.jwtDecoder.decode(any())).thenReturn(Mono.error(new JwtException("Oops")));

		assertThatCode(() -> this.manager.authenticate(token).block())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void authenticateWhenNotJwtExceptionThenPropagates() {
		BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken("token-1");
		when(this.jwtDecoder.decode(any())).thenReturn(Mono.error(new RuntimeException("Oops")));

		assertThatCode(() -> this.manager.authenticate(token).block())
				.isInstanceOf(RuntimeException.class);
	}

	@Test
	public void authenticateWhenJwtThenSuccess() {
		BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken("token-1");
		when(this.jwtDecoder.decode(token.getToken())).thenReturn(Mono.just(this.jwt));

		Authentication authentication = this.manager.authenticate(token).block();

		assertThat(authentication).isNotNull();
		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsOnly("SCOPE_message:read", "SCOPE_message:write");
	}
}
