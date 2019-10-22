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

package org.springframework.security.authentication;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingReactiveAuthenticationManagerTests {
	@Mock
	ReactiveAuthenticationManager delegate1;

	@Mock
	ReactiveAuthenticationManager delegate2;

	@Mock
	Authentication authentication;

	@Mock
	Authentication otherAuthentication;

	@Test
	public void authenticateWhenEmptyAndNotThenReturnsNotEmpty() {
		when(this.delegate1.authenticate(any())).thenReturn(Mono.empty());
		when(this.delegate2.authenticate(any())).thenReturn(Mono.just(this.authentication));

		DelegatingReactiveAuthenticationManager manager = new DelegatingReactiveAuthenticationManager(this.delegate1, this.delegate2);

		assertThat(manager.authenticate(this.authentication).block()).isEqualTo(this.authentication);
	}

	@Test
	public void authenticateWhenNotEmptyThenOtherDelegatesNotSubscribed() {
		// delay to try and force delegate2 to finish (i.e. make sure we didn't use flatMap)
		when(this.delegate1.authenticate(any())).thenReturn(Mono.just(this.authentication).delayElement(Duration.ofMillis(100)));

		DelegatingReactiveAuthenticationManager manager = new DelegatingReactiveAuthenticationManager(this.delegate1, this.delegate2);

		StepVerifier.create(manager.authenticate(this.authentication))
			.expectNext(this.authentication)
			.verifyComplete();
	}

	@Test
	public void authenticateWhenBadCredentialsThenDelegate2NotInvokedAndError() {
		when(this.delegate1.authenticate(any())).thenReturn(Mono.error(new BadCredentialsException("Test")));
		when(this.delegate2.authenticate(any())).thenReturn(Mono.just(otherAuthentication));

		DelegatingReactiveAuthenticationManager manager = new DelegatingReactiveAuthenticationManager(this.delegate1, this.delegate2);

		StepVerifier.create(manager.authenticate(this.authentication))
			.expectNext(otherAuthentication)
			.verifyComplete();
	}

	@Test
	public void authenticationWhenBadCredentialsThenCredentialsExpiredExceptionIsLastError(){
		when(this.delegate1.authenticate(any())).thenReturn(Mono.error(new BadCredentialsException("Test")));
		when(this.delegate2.authenticate(any())).thenReturn(Mono.error(new CredentialsExpiredException("Test2")));

		DelegatingReactiveAuthenticationManager manager = new DelegatingReactiveAuthenticationManager(this.delegate1, this.delegate2);

		StepVerifier.create(manager.authenticate(this.authentication))
				.expectError(CredentialsExpiredException.class)
				.verifyThenAssertThat()
				.hasOperatorErrors(2);
	}
}
