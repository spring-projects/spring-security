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

package org.springframework.security.authentication.ott;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.SecurityAssertions;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.CollectionUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

/**
 * Tests for {@link OneTimeTokenAuthenticationProvider}.
 *
 * @author Max Batischev
 */
@ExtendWith(MockitoExtension.class)
public class OneTimeTokenAuthenticationProviderTests {

	private static final String TOKEN = "token";

	private static final String USERNAME = "Max";

	private static final String PASSWORD = "password";

	@Mock
	private OneTimeTokenService oneTimeTokenService;

	@Mock
	private UserDetailsService userDetailsService;

	@InjectMocks
	private OneTimeTokenAuthenticationProvider provider;

	@Test
	void authenticateWhenAuthenticationTokenIsPresentThenAuthenticates() {
		given(this.oneTimeTokenService.consume(any()))
			.willReturn(new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now().plusSeconds(120)));
		given(this.userDetailsService.loadUserByUsername(anyString()))
			.willReturn(new User(USERNAME, PASSWORD, List.of()));
		OneTimeTokenAuthenticationToken token = new OneTimeTokenAuthenticationToken(TOKEN);

		Authentication authentication = this.provider.authenticate(token);

		User user = (User) authentication.getPrincipal();
		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(user.getUsername()).isEqualTo(USERNAME);
		assertThat(user.getPassword()).isEqualTo(PASSWORD);
		assertThat(CollectionUtils.isEmpty(user.getAuthorities())).isTrue();
	}

	@Test
	void authenticateWhenOneTimeTokenIsNotFoundThenFails() {
		given(this.oneTimeTokenService.consume(any())).willReturn(null);
		OneTimeTokenAuthenticationToken token = new OneTimeTokenAuthenticationToken(TOKEN);

		assertThatExceptionOfType(InvalidOneTimeTokenException.class)
			.isThrownBy(() -> this.provider.authenticate(token));
	}

	@Test
	void authenticateWhenUserIsNotFoundThenFails() {
		given(this.oneTimeTokenService.consume(any()))
			.willReturn(new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now().plusSeconds(120)));
		given(this.userDetailsService.loadUserByUsername(anyString())).willThrow(UsernameNotFoundException.class);
		OneTimeTokenAuthenticationToken token = new OneTimeTokenAuthenticationToken(TOKEN);

		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> this.provider.authenticate(token));
	}

	@Test
	void authenticateWhenSuccessThenIssuesFactor() {
		given(this.oneTimeTokenService.consume(any()))
			.willReturn(new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now().plusSeconds(120)));
		given(this.userDetailsService.loadUserByUsername(anyString()))
			.willReturn(new User(USERNAME, PASSWORD, List.of()));
		OneTimeTokenAuthenticationToken token = new OneTimeTokenAuthenticationToken(TOKEN);

		Authentication authentication = this.provider.authenticate(token);
		SecurityAssertions.assertThat(authentication).hasAuthority(FactorGrantedAuthority.OTT_AUTHORITY);
	}

	@Test
	void constructorWhenOneTimeTokenServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OneTimeTokenAuthenticationProvider(null, this.userDetailsService))
				.withMessage("oneTimeTokenService cannot be null");
		// @formatter:on
	}

	@Test
	void constructorWhenUserDetailsServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OneTimeTokenAuthenticationProvider(this.oneTimeTokenService, null))
				.withMessage("userDetailsService cannot be null");
		// @formatter:on
	}

}
