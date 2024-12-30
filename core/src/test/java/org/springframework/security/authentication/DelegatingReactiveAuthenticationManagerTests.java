/*
 * Copyright 2002-2024 the original author or authors.
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

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.1
 */
@ExtendWith(MockitoExtension.class)
public class DelegatingReactiveAuthenticationManagerTests {

	@Mock
	ReactiveAuthenticationManager delegate1;

	@Mock
	ReactiveAuthenticationManager delegate2;

	@Mock
	Authentication authentication;

	@Test
	public void authenticateWhenEmptyAndNotThenReturnsNotEmpty() {
		given(this.delegate1.authenticate(any())).willReturn(Mono.empty());
		given(this.delegate2.authenticate(any())).willReturn(Mono.just(this.authentication));
		DelegatingReactiveAuthenticationManager manager = new DelegatingReactiveAuthenticationManager(this.delegate1,
				this.delegate2);
		assertThat(manager.authenticate(this.authentication).block()).isEqualTo(this.authentication);
	}

	@Test
	public void authenticateWhenNotEmptyThenOtherDelegatesNotSubscribed() {
		// delay to try and force delegate2 to finish (i.e. make sure we didn't use
		// flatMap)
		given(this.delegate1.authenticate(any()))
			.willReturn(Mono.just(this.authentication).delayElement(Duration.ofMillis(100)));
		DelegatingReactiveAuthenticationManager manager = new DelegatingReactiveAuthenticationManager(this.delegate1,
				this.delegate2);
		StepVerifier.create(manager.authenticate(this.authentication)).expectNext(this.authentication).verifyComplete();
	}

	@Test
	public void authenticateWhenBadCredentialsThenDelegate2NotInvokedAndError() {
		given(this.delegate1.authenticate(any())).willReturn(Mono.error(new BadCredentialsException("Test")));
		DelegatingReactiveAuthenticationManager manager = new DelegatingReactiveAuthenticationManager(this.delegate1,
				this.delegate2);
		StepVerifier.create(manager.authenticate(this.authentication))
			.expectError(BadCredentialsException.class)
			.verify();
	}

	@Test
	public void authenticateWhenContinueOnErrorAndFirstBadCredentialsThenTriesSecond() {
		given(this.delegate1.authenticate(any())).willReturn(Mono.error(new BadCredentialsException("Test")));
		given(this.delegate2.authenticate(any())).willReturn(Mono.just(this.authentication));

		DelegatingReactiveAuthenticationManager manager = managerWithContinueOnError();

		assertThat(manager.authenticate(this.authentication).block()).isEqualTo(this.authentication);
	}

	@Test
	public void authenticateWhenContinueOnErrorAndBothDelegatesBadCredentialsThenError() {
		given(this.delegate1.authenticate(any())).willReturn(Mono.error(new BadCredentialsException("Test")));
		given(this.delegate2.authenticate(any())).willReturn(Mono.error(new BadCredentialsException("Test")));

		DelegatingReactiveAuthenticationManager manager = managerWithContinueOnError();

		StepVerifier.create(manager.authenticate(this.authentication))
			.expectError(BadCredentialsException.class)
			.verify();
	}

	@Test
	public void authenticateWhenContinueOnErrorAndDelegate1NotEmptyThenReturnsNotEmpty() {
		given(this.delegate1.authenticate(any())).willReturn(Mono.just(this.authentication));

		DelegatingReactiveAuthenticationManager manager = managerWithContinueOnError();

		assertThat(manager.authenticate(this.authentication).block()).isEqualTo(this.authentication);
	}

	private DelegatingReactiveAuthenticationManager managerWithContinueOnError() {
		DelegatingReactiveAuthenticationManager manager = new DelegatingReactiveAuthenticationManager(this.delegate1,
				this.delegate2);
		manager.setContinueOnError(true);

		return manager;
	}

}
