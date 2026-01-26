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

package org.springframework.security.authentication.ott.reactive;

import java.time.Instant;
import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OneTimeTokenReactiveAuthenticationManager}
 *
 * @author Max Batischev
 */
public class OneTimeTokenReactiveAuthenticationManagerTests {

	private ReactiveAuthenticationManager authenticationManager;

	private static final String USERNAME = "user";

	private static final String PASSWORD = "password";

	private static final String TOKEN = "token";

	@Test
	@SuppressWarnings("removal")
	public void constructorWhenOneTimeTokenServiceNullThenIllegalArgumentException() {
		ReactiveUserDetailsService userDetailsService = mock(ReactiveUserDetailsService.class);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OneTimeTokenReactiveAuthenticationManager(null, userDetailsService));
		// @formatter:on
	}

	@Test
	@SuppressWarnings("removal")
	public void constructorWhenUserDetailsServiceNullThenIllegalArgumentException() {
		ReactiveOneTimeTokenService oneTimeTokenService = mock(ReactiveOneTimeTokenService.class);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OneTimeTokenReactiveAuthenticationManager(oneTimeTokenService, null));
		// @formatter:on
	}

	@Test
	@SuppressWarnings("removal")
	void authenticateWhenOneTimeTokenAuthenticationTokenIsPresentThenSuccess() {
		ReactiveOneTimeTokenService oneTimeTokenService = mock(ReactiveOneTimeTokenService.class);
		given(oneTimeTokenService.consume(ArgumentMatchers.any(OneTimeTokenAuthenticationToken.class)))
			.willReturn(Mono.just(new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now())));
		ReactiveUserDetailsService userDetailsService = mock(ReactiveUserDetailsService.class);
		User testUser = new User(USERNAME, PASSWORD, AuthorityUtils.createAuthorityList("TEST"));
		given(userDetailsService.findByUsername(eq(USERNAME))).willReturn(Mono.just(testUser));

		this.authenticationManager = new OneTimeTokenReactiveAuthenticationManager(oneTimeTokenService,
				userDetailsService);

		Authentication token = this.authenticationManager
			.authenticate(OneTimeTokenAuthenticationToken.unauthenticated(TOKEN))
			.block();

		UserDetails user = (UserDetails) token.getPrincipal();
		Collection<? extends GrantedAuthority> authorities = token.getAuthorities();

		assertThat(user).isNotNull();
		assertThat(user.getUsername()).isEqualTo(USERNAME);
		assertThat(user.getPassword()).isEqualTo(PASSWORD);
		assertThat(token.isAuthenticated()).isTrue();
		assertThat(CollectionUtils.isEmpty(authorities)).isFalse();
	}

	@Test
	@SuppressWarnings("removal")
	void authenticateWhenInvalidOneTimeTokenAuthenticationTokenIsPresentThenFail() {
		ReactiveOneTimeTokenService oneTimeTokenService = mock(ReactiveOneTimeTokenService.class);
		given(oneTimeTokenService.consume(ArgumentMatchers.any(OneTimeTokenAuthenticationToken.class)))
			.willReturn(Mono.empty());
		ReactiveUserDetailsService userDetailsService = mock(ReactiveUserDetailsService.class);

		this.authenticationManager = new OneTimeTokenReactiveAuthenticationManager(oneTimeTokenService,
				userDetailsService);

		// @formatter:off
		assertThatExceptionOfType(InvalidOneTimeTokenException.class)
				.isThrownBy(() -> this.authenticationManager.authenticate(OneTimeTokenAuthenticationToken.unauthenticated(TOKEN))
						.block());
		// @formatter:on
	}

	@Test
	@SuppressWarnings("removal")
	void authenticateWhenIncorrectTypeOfAuthenticationIsPresentThenFail() {
		ReactiveOneTimeTokenService oneTimeTokenService = mock(ReactiveOneTimeTokenService.class);
		given(oneTimeTokenService.consume(ArgumentMatchers.any(OneTimeTokenAuthenticationToken.class)))
			.willReturn(Mono.empty());
		ReactiveUserDetailsService userDetailsService = mock(ReactiveUserDetailsService.class);

		this.authenticationManager = new OneTimeTokenReactiveAuthenticationManager(oneTimeTokenService,
				userDetailsService);

		// @formatter:off
		Authentication authentication = this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(USERNAME, PASSWORD))
				.block();
		// @formatter:on

		assertThat(authentication).isNull();
	}

}
