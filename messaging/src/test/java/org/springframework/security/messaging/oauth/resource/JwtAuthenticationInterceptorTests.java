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

package org.springframework.security.messaging.oauth.resource;

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link JwtAuthenticationInterceptor}
 *
 * @author Josh Long
 */
public class JwtAuthenticationInterceptorTests {

	private static final String TOKEN_HEADER_NAME = "authorization";

	private static final String AUTHENTICATION_HEADER_NAME = "authentication";

	private static final String TOKEN = "token";

	private final JwtDecoder jwtDecoder = mock(JwtDecoder.class);

	private final MessageChannel channel = mock(MessageChannel.class);

	private JwtAuthenticationInterceptor interceptor;

	@BeforeEach
	public void setup() {
		this.interceptor = new JwtAuthenticationInterceptor(TOKEN_HEADER_NAME, AUTHENTICATION_HEADER_NAME,
				new JwtAuthenticationProvider(this.jwtDecoder));
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> new JwtAuthenticationInterceptor(TOKEN_HEADER_NAME,
				AUTHENTICATION_HEADER_NAME, (AuthenticationManager) null));
	}

	@Test
	public void constructorWhenTokenHeaderNameEmptyThenIllegalArgument() {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new JwtAuthenticationInterceptor("", AUTHENTICATION_HEADER_NAME, authenticationManager));
	}

	@Test
	public void constructorWhenAuthenticationHeaderNameNullThenIllegalArgument() {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new JwtAuthenticationInterceptor(TOKEN_HEADER_NAME, null, authenticationManager));
	}

	@Test
	public void constructorWhenAuthenticationHeaderNameEmptyThenIllegalArgument() {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new JwtAuthenticationInterceptor(TOKEN_HEADER_NAME, "", authenticationManager));
	}

	@Test
	public void preSendWhenValidTokenThenAuthenticationHeaderSet() {
		given(this.jwtDecoder.decode(TOKEN)).willReturn(jwt());
		Message<?> message = this.interceptor.preSend(message(TOKEN), this.channel);
		Object header = message.getHeaders().get(AUTHENTICATION_HEADER_NAME);
		assertThat(header).isInstanceOf(Authentication.class);
		Authentication authentication = (Authentication) header;
		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getName()).isEqualTo("user");
		assertThat(authentication.getPrincipal()).isInstanceOf(Jwt.class);
	}

	@Test
	public void preSendWhenValidTokenThenAuthoritiesRetained() {
		given(this.jwtDecoder.decode(TOKEN)).willReturn(jwt());
		Message<?> message = this.interceptor.preSend(message(TOKEN), this.channel);
		Authentication authentication = (Authentication) message.getHeaders().get(AUTHENTICATION_HEADER_NAME);
		assertThat(AuthorityUtils.authorityListToSet(authentication.getAuthorities())).contains("SCOPE_read");
	}

	@Test
	public void preSendWhenValidTokenThenTokenHeaderRetained() {
		given(this.jwtDecoder.decode(TOKEN)).willReturn(jwt());
		Message<?> message = this.interceptor.preSend(message(TOKEN), this.channel);
		assertThat(message.getHeaders().get(TOKEN_HEADER_NAME)).isEqualTo(TOKEN);
		assertThat(message.getPayload()).isEqualTo("payload");
	}

	@Test
	public void preSendWhenAuthenticationManagerThenAuthenticationHeaderSet() {
		Authentication authenticated = new TestingAuthenticationToken("user", "token", "ROLE_USER");
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		given(authenticationManager.authenticate(any())).willReturn(authenticated);
		JwtAuthenticationInterceptor interceptor = new JwtAuthenticationInterceptor(TOKEN_HEADER_NAME,
				AUTHENTICATION_HEADER_NAME, authenticationManager);
		Message<?> message = interceptor.preSend(message(TOKEN), this.channel);
		assertThat(message.getHeaders().get(AUTHENTICATION_HEADER_NAME)).isSameAs(authenticated);
	}

	@Test
	public void preSendWhenAuthenticationProviderReturnsNullThenBadCredentials() {
		AuthenticationProvider authenticationProvider = mock(AuthenticationProvider.class);
		given(authenticationProvider.authenticate(any())).willReturn(null);
		JwtAuthenticationInterceptor interceptor = new JwtAuthenticationInterceptor(TOKEN_HEADER_NAME,
				AUTHENTICATION_HEADER_NAME, authenticationProvider);
		Message<?> message = message(TOKEN);
		assertThatExceptionOfType(BadCredentialsException.class)
			.isThrownBy(() -> interceptor.preSend(message, this.channel));
	}

	@Test
	public void preSendWhenInvalidTokenThenException() {
		willThrow(new BadJwtException("invalid")).given(this.jwtDecoder).decode(any());
		Message<?> message = message(TOKEN);
		assertThatExceptionOfType(InvalidBearerTokenException.class)
			.isThrownBy(() -> this.interceptor.preSend(message, this.channel));
	}

	@Test
	public void preSendWhenNoHeaderThenIllegalState() {
		Message<?> message = MessageBuilder.withPayload("payload").build();
		assertThatIllegalStateException().isThrownBy(() -> this.interceptor.preSend(message, this.channel));
	}

	@Test
	public void preSendWhenEmptyTokenThenIllegalArgument() {
		Message<?> message = message("");
		assertThatIllegalArgumentException().isThrownBy(() -> this.interceptor.preSend(message, this.channel));
	}

	private static Message<?> message(String token) {
		return MessageBuilder.withPayload("payload").setHeader(TOKEN_HEADER_NAME, token).build();
	}

	private static Jwt jwt() {
		// @formatter:off
		return Jwt.withTokenValue(TOKEN)
				.header("alg", "none")
				.subject("user")
				.claim("scope", "read")
				.issuedAt(Instant.EPOCH)
				.expiresAt(Instant.MAX)
				.build();
		// @formatter:on
	}

}
