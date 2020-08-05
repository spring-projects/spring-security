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

package org.springframework.security.core.context;

import org.junit.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class ReactiveSecurityContextHolderTests {

	@Test
	public void getContextWhenEmpty() {
		Mono<SecurityContext> context = ReactiveSecurityContextHolder.getContext();

		StepVerifier.create(context).verifyComplete();
	}

	@Test
	public void setContextAndGetContextThenEmitsContext() {
		SecurityContext expectedContext = new SecurityContextImpl(
				new TestingAuthenticationToken("user", "password", "ROLE_USER"));

		Mono<SecurityContext> context = Mono.subscriberContext()
				.flatMap(c -> ReactiveSecurityContextHolder.getContext())
				.subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(expectedContext)));

		StepVerifier.create(context).expectNext(expectedContext).verifyComplete();
	}

	@Test
	public void demo() {
		Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");

		Mono<String> messageByUsername = ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication).map(Authentication::getName)
				.flatMap(this::findMessageByUsername)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		StepVerifier.create(messageByUsername).expectNext("Hi user").verifyComplete();
	}

	private Mono<String> findMessageByUsername(String username) {
		return Mono.just("Hi " + username);
	}

	@Test
	public void setContextAndClearAndGetContextThenEmitsEmpty() {
		SecurityContext expectedContext = new SecurityContextImpl(
				new TestingAuthenticationToken("user", "password", "ROLE_USER"));

		Mono<SecurityContext> context = Mono.subscriberContext()
				.flatMap(c -> ReactiveSecurityContextHolder.getContext())
				.subscriberContext(ReactiveSecurityContextHolder.clearContext())
				.subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(expectedContext)));

		StepVerifier.create(context).verifyComplete();
	}

	@Test
	public void setAuthenticationAndGetContextThenEmitsContext() {
		Authentication expectedAuthentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");

		Mono<Authentication> authentication = Mono.subscriberContext()
				.flatMap(c -> ReactiveSecurityContextHolder.getContext()).map(SecurityContext::getAuthentication)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(expectedAuthentication));

		StepVerifier.create(authentication).expectNext(expectedAuthentication).verifyComplete();
	}

}
