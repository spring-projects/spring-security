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

import org.junit.Test;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import reactor.core.publisher.Mono;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Alexey Nesterov
 * @since 5.2
 */
public class ReactivePreAuthenticatedAuthenticationManagerTests {

	private ReactiveUserDetailsService mockUserDetailsService
			= mock(ReactiveUserDetailsService.class);

	private ReactivePreAuthenticatedAuthenticationManager manager
			= new ReactivePreAuthenticatedAuthenticationManager(mockUserDetailsService);

	private final User validAccount = new User("valid", "", Collections.emptySet());
	private final User nonExistingAccount = new User("non existing", "", Collections.emptySet());
	private final User disabledAccount = new User("disabled", "", false, true, true, true, Collections.emptySet());
	private final User expiredAccount = new User("expired", "", true, false, true, true, Collections.emptySet());
	private final User accountWithExpiredCredentials = new User("credentials expired", "", true, true, false, true, Collections.emptySet());
	private final User lockedAccount = new User("locked", "", true, true, true, false, Collections.emptySet());

	@Test
	public void returnsAuthenticatedTokenForValidAccount() {
		when(mockUserDetailsService.findByUsername(anyString())).thenReturn(Mono.just(validAccount));

		Authentication authentication = manager.authenticate(tokenForUser(validAccount.getUsername())).block();
		assertThat(authentication.isAuthenticated()).isEqualTo(true);
	}

	@Test(expected = UsernameNotFoundException.class)
	public void returnsNullForNonExistingAccount() {
		when(mockUserDetailsService.findByUsername(anyString())).thenReturn(Mono.empty());

		manager.authenticate(tokenForUser(nonExistingAccount.getUsername())).block();
	}

	@Test(expected = LockedException.class)
	public void throwsExceptionForLockedAccount() {
		when(mockUserDetailsService.findByUsername(anyString())).thenReturn(Mono.just(lockedAccount));

		manager.authenticate(tokenForUser(lockedAccount.getUsername())).block();
	}

	@Test(expected = DisabledException.class)
	public void throwsExceptionForDisabledAccount() {
		when(mockUserDetailsService.findByUsername(anyString())).thenReturn(Mono.just(disabledAccount));

		manager.authenticate(tokenForUser(disabledAccount.getUsername())).block();
	}

	@Test(expected = AccountExpiredException.class)
	public void throwsExceptionForExpiredAccount() {
		when(mockUserDetailsService.findByUsername(anyString())).thenReturn(Mono.just(expiredAccount));

		manager.authenticate(tokenForUser(expiredAccount.getUsername())).block();
	}


	@Test(expected = CredentialsExpiredException.class)
	public void throwsExceptionForAccountWithExpiredCredentials() {
		when(mockUserDetailsService.findByUsername(anyString())).thenReturn(Mono.just(accountWithExpiredCredentials));

		manager.authenticate(tokenForUser(accountWithExpiredCredentials.getUsername())).block();
	}

	private Authentication tokenForUser(String username) {
		return new PreAuthenticatedAuthenticationToken(username, null);
	}
}
