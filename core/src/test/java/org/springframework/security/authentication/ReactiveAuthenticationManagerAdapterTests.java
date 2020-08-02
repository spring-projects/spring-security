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
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

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
		this.manager = new ReactiveAuthenticationManagerAdapter(this.delegate);
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
		given(this.delegate.authenticate(any())).willReturn(this.authentication);
		given(this.authentication.isAuthenticated()).willReturn(true);
		Authentication result = this.manager.authenticate(this.authentication).block();
		assertThat(result).isEqualTo(this.authentication);
	}

	@Test
	public void authenticateWhenReturnNotAuthenticatedThenError() {
		given(this.delegate.authenticate(any())).willReturn(this.authentication);
		Authentication result = this.manager.authenticate(this.authentication).block();
		assertThat(result).isNull();
	}

	@Test
	public void authenticateWhenBadCredentialsThenError() {
		given(this.delegate.authenticate(any())).willThrow(new BadCredentialsException("Failed"));
		Mono<Authentication> result = this.manager.authenticate(this.authentication);
		StepVerifier.create(result).expectError(BadCredentialsException.class).verify();
	}

}
