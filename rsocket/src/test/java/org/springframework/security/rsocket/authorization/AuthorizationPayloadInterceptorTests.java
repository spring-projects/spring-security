/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.authorization;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;
import reactor.util.context.Context;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadInterceptorChain;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthorizationPayloadInterceptorTests {

	@Mock
	private ReactiveAuthorizationManager<PayloadExchange> authorizationManager;

	@Mock
	private PayloadExchange exchange;

	@Mock
	private PayloadInterceptorChain chain;

	private PublisherProbe<Void> managerResult = PublisherProbe.empty();

	private PublisherProbe<Void> chainResult = PublisherProbe.empty();

	@Test
	public void interceptWhenAuthenticationEmptyAndSubscribedThenException() {
		given(this.chain.next(any())).willReturn(this.chainResult.mono());

		AuthorizationPayloadInterceptor interceptor = new AuthorizationPayloadInterceptor(
				AuthenticatedReactiveAuthorizationManager.authenticated());

		StepVerifier.create(interceptor.intercept(this.exchange, this.chain))
				.then(() -> this.chainResult.assertWasNotSubscribed())
				.verifyError(AuthenticationCredentialsNotFoundException.class);
	}

	@Test
	public void interceptWhenAuthenticationNotSubscribedAndEmptyThenCompletes() {
		given(this.chain.next(any())).willReturn(this.chainResult.mono());
		given(this.authorizationManager.verify(any(), any())).willReturn(this.managerResult.mono());

		AuthorizationPayloadInterceptor interceptor = new AuthorizationPayloadInterceptor(this.authorizationManager);

		StepVerifier.create(interceptor.intercept(this.exchange, this.chain))
				.then(() -> this.chainResult.assertWasSubscribed()).verifyComplete();
	}

	@Test
	public void interceptWhenNotAuthorizedThenException() {
		given(this.chain.next(any())).willReturn(this.chainResult.mono());

		AuthorizationPayloadInterceptor interceptor = new AuthorizationPayloadInterceptor(
				AuthorityReactiveAuthorizationManager.hasRole("USER"));
		Context userContext = ReactiveSecurityContextHolder
				.withAuthentication(new TestingAuthenticationToken("user", "password"));

		Mono<Void> intercept = interceptor.intercept(this.exchange, this.chain).subscriberContext(userContext);

		StepVerifier.create(intercept).then(() -> this.chainResult.assertWasNotSubscribed())
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void interceptWhenAuthorizedThenContinues() {
		given(this.chain.next(any())).willReturn(this.chainResult.mono());

		AuthorizationPayloadInterceptor interceptor = new AuthorizationPayloadInterceptor(
				AuthenticatedReactiveAuthorizationManager.authenticated());
		Context userContext = ReactiveSecurityContextHolder
				.withAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"));

		Mono<Void> intercept = interceptor.intercept(this.exchange, this.chain).subscriberContext(userContext);

		StepVerifier.create(intercept).then(() -> this.chainResult.assertWasSubscribed()).verifyComplete();
	}

}
