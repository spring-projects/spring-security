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

package org.springframework.security.web.server.authentication;

import java.util.Collections;

import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * @author Alexey Nesterov
 * @since 5.2
 */
public class ReactivePreAuthenticatedAuthenticationManagerTests {

	private ReactiveUserDetailsService mockUserDetailsService = mock(ReactiveUserDetailsService.class);

	private ReactivePreAuthenticatedAuthenticationManager manager = new ReactivePreAuthenticatedAuthenticationManager(
			this.mockUserDetailsService);

	private final User validAccount = new User("valid", "", Collections.emptySet());

	private final User nonExistingAccount = new User("non existing", "", Collections.emptySet());

	private final User disabledAccount = new User("disabled", "", false, true, true, true, Collections.emptySet());

	private final User expiredAccount = new User("expired", "", true, false, true, true, Collections.emptySet());

	private final User accountWithExpiredCredentials = new User("credentials expired", "", true, true, false, true,
			Collections.emptySet());

	private final User lockedAccount = new User("locked", "", true, true, true, false, Collections.emptySet());

	@Test
	public void returnsAuthenticatedTokenForValidAccount() {
		given(this.mockUserDetailsService.findByUsername(anyString())).willReturn(Mono.just(this.validAccount));
		Authentication authentication = this.manager.authenticate(tokenForUser(this.validAccount.getUsername()))
				.block();
		assertThat(authentication.isAuthenticated()).isEqualTo(true);
	}

	@Test
	public void returnsNullForNonExistingAccount() {
		given(this.mockUserDetailsService.findByUsername(anyString())).willReturn(Mono.empty());
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(
				() -> this.manager.authenticate(tokenForUser(this.nonExistingAccount.getUsername())).block());
	}

	@Test
	public void throwsExceptionForLockedAccount() {
		given(this.mockUserDetailsService.findByUsername(anyString())).willReturn(Mono.just(this.lockedAccount));
		assertThatExceptionOfType(LockedException.class)
				.isThrownBy(() -> this.manager.authenticate(tokenForUser(this.lockedAccount.getUsername())).block());
	}

	@Test
	public void throwsExceptionForDisabledAccount() {
		given(this.mockUserDetailsService.findByUsername(anyString())).willReturn(Mono.just(this.disabledAccount));
		assertThatExceptionOfType(DisabledException.class)
				.isThrownBy(() -> this.manager.authenticate(tokenForUser(this.disabledAccount.getUsername())).block());
	}

	@Test
	public void throwsExceptionForExpiredAccount() {
		given(this.mockUserDetailsService.findByUsername(anyString())).willReturn(Mono.just(this.expiredAccount));
		assertThatExceptionOfType(AccountExpiredException.class)
				.isThrownBy(() -> this.manager.authenticate(tokenForUser(this.expiredAccount.getUsername())).block());
	}

	@Test
	public void throwsExceptionForAccountWithExpiredCredentials() {
		given(this.mockUserDetailsService.findByUsername(anyString()))
				.willReturn(Mono.just(this.accountWithExpiredCredentials));
		assertThatExceptionOfType(CredentialsExpiredException.class).isThrownBy(() -> this.manager
				.authenticate(tokenForUser(this.accountWithExpiredCredentials.getUsername())).block());
	}

	private Authentication tokenForUser(String username) {
		return new PreAuthenticatedAuthenticationToken(username, null);
	}

}
