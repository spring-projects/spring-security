/*
 * Copyright 2002-2017 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class ReactiveAuthenticationManagerAdapterTests {
	@Mock
	AuthenticationManager delegate;
	@Mock
	Authentication authentication;

	ReactiveAuthenticationManagerAdapter manager;

	@Before
	public void setup() {
		manager = new ReactiveAuthenticationManagerAdapter(delegate);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullAuthenticationManager() {
		new ReactiveAuthenticationManagerAdapter(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setSchedulerNull() {
		this.manager.setScheduler(null);
	}

	@Test
	public void authenticateWhenSuccessThenSuccess() {
		when(delegate.authenticate(any())).thenReturn(authentication);
		when(authentication.isAuthenticated()).thenReturn(true);

		Authentication result = manager.authenticate(authentication).block();

		assertThat(result).isEqualTo(authentication);
	}

	@Test
	public void authenticateWhenReturnNotAuthenticatedThenError() {
		when(delegate.authenticate(any())).thenReturn(authentication);

		Authentication result = manager.authenticate(authentication).block();

		assertThat(result).isNull();
	}

	@Test
	public void authenticateWhenBadCredentialsThenError() {
		when(delegate.authenticate(any())).thenThrow(new BadCredentialsException("Failed"));

		Mono<Authentication> result = manager.authenticate(authentication);

		StepVerifier.create(result)
			.expectError(BadCredentialsException.class)
			.verify();
	}
}
