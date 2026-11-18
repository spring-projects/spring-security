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

package org.springframework.security.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link CachingUserDetailsService}.
 *
 * @author Matheus Leal
 */
@ExtendWith(MockitoExtension.class)
public class CachingUserDetailsServiceTests {

	@Mock
	UserDetailsService delegate;

	@Mock
	UserCache userCache;

	CachingUserDetailsService service;

	UserDetails user = PasswordEncodedUser.user();

	@BeforeEach
	public void setup() {
		this.service = new CachingUserDetailsService(this.delegate);
		this.service.setUserCache(this.userCache);
	}

	@Test
	public void loadUserByUsernameWhenUserNotInCacheThenLoadsFromDelegateAndPutsInCache() {
		given(this.delegate.loadUserByUsername("user")).willReturn(this.user);
		UserDetails result = this.service.loadUserByUsername("user");
		assertThat(result).isSameAs(this.user);
		verify(this.userCache).putUserInCache(this.user);
	}

	@Test
	public void loadUserByUsernameWhenUserInCacheThenDoesNotPutUserInCacheAgain() {
		given(this.userCache.getUserFromCache("user")).willReturn(this.user);
		UserDetails result = this.service.loadUserByUsername("user");
		assertThat(result).isSameAs(this.user);
		verifyNoInteractions(this.delegate);
		verify(this.userCache, never()).putUserInCache(any());
	}

	@Test
	public void loadUserByUsernameWhenDelegateReturnsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.service.loadUserByUsername("user"));
		verify(this.userCache, never()).putUserInCache(any());
	}

}
