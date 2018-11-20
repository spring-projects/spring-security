/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.test.context.support;

/**
 * @author Rob Winch
 * @since 5.0
 */

import java.util.concurrent.ForkJoinPool;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.core.OrderComparator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.context.TestContext;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class ReactorContextTestExecutionListenerTests {

	@Mock
	private TestContext testContext;

	private ReactorContextTestExecutionListener listener =
		new ReactorContextTestExecutionListener();

	@After
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
		Hooks.resetOnLastOperator();
	}

	@Test
	public void beforeTestMethodWhenSecurityContextEmptyThenReactorContextNull() throws Exception {
		this.listener.beforeTestMethod(this.testContext);

		Mono<?> result = ReactiveSecurityContextHolder
			.getContext();

		StepVerifier.create(result)
			.verifyComplete();
	}

	@Test
	public void beforeTestMethodWhenNullAuthenticationThenReactorContextNull() throws Exception {
		TestSecurityContextHolder.setContext(new SecurityContextImpl());

		this.listener.beforeTestMethod(this.testContext);

		Mono<?> result = ReactiveSecurityContextHolder
			.getContext();

		StepVerifier.create(result)
			.verifyComplete();
	}

	@Test
	public void beforeTestMethodWhenAuthenticationThenReactorContextHasAuthentication() throws Exception {
		TestingAuthenticationToken expectedAuthentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		TestSecurityContextHolder.setAuthentication(expectedAuthentication);

		this.listener.beforeTestMethod(this.testContext);

		assertAuthentication(expectedAuthentication);
	}

	@Test
	public void beforeTestMethodWhenCustomContext() throws Exception {
		TestingAuthenticationToken expectedAuthentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContext context = new CustomContext(expectedAuthentication);
		TestSecurityContextHolder.setContext(context);

		this.listener.beforeTestMethod(this.testContext);

		assertSecurityContext(context);
	}

	static class CustomContext implements SecurityContext {
		private Authentication authentication;

		CustomContext(Authentication authentication) {
			this.authentication = authentication;
		}

		@Override
		public Authentication getAuthentication() {
			return this.authentication;
		}

		@Override
		public void setAuthentication(Authentication authentication) {
			this.authentication = authentication;
		}
	}

	@Test
	public void beforeTestMethodWhenExistingAuthenticationThenReactorContextHasOriginalAuthentication() throws Exception {
		TestingAuthenticationToken expectedAuthentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		TestingAuthenticationToken contextHolder = new TestingAuthenticationToken("contextHolder", "password", "ROLE_USER");
		TestSecurityContextHolder.setAuthentication(contextHolder);

		this.listener.beforeTestMethod(this.testContext);

		Mono<Authentication> authentication = Mono.just("any")
			.flatMap(s -> ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
			)
			.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(expectedAuthentication));

		StepVerifier.create(authentication)
			.expectNext(expectedAuthentication)
			.verifyComplete();
	}

	@Test
	public void beforeTestMethodWhenClearThenReactorContextDoesNotOverride() throws Exception {
		TestingAuthenticationToken expectedAuthentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		TestingAuthenticationToken contextHolder = new TestingAuthenticationToken("contextHolder", "password", "ROLE_USER");
		TestSecurityContextHolder.setAuthentication(contextHolder);

		this.listener.beforeTestMethod(this.testContext);

		Mono<Authentication> authentication = Mono.just("any")
			.flatMap(s -> ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
			)
			.subscriberContext(ReactiveSecurityContextHolder.clearContext());

		StepVerifier.create(authentication)
			.verifyComplete();
	}

	@Test
	public void afterTestMethodWhenSecurityContextEmptyThenNoError() throws Exception {
		this.listener.beforeTestMethod(this.testContext);

		this.listener.afterTestMethod(this.testContext);
	}

	@Test
	public void afterTestMethodWhenSetupThenReactorContextNull() throws Exception {
		beforeTestMethodWhenAuthenticationThenReactorContextHasAuthentication();

		this.listener.afterTestMethod(this.testContext);

		assertThat(Mono.subscriberContext().block().isEmpty()).isTrue();
	}

	@Test
	public void afterTestMethodWhenDifferentHookIsRegistered() throws Exception {
		Object obj = new Object();

		Hooks.onLastOperator("CUSTOM_HOOK", p -> Mono.just(obj));
		this.listener.afterTestMethod(this.testContext);

		assertThat(Mono.subscriberContext().block()).isEqualTo(obj);
	}

	@Test
	public void orderWhenComparedToWithSecurityContextTestExecutionListenerIsAfter() {
		OrderComparator comparator = new OrderComparator();
		WithSecurityContextTestExecutionListener withSecurity = new WithSecurityContextTestExecutionListener();
		ReactorContextTestExecutionListener reactorContext = new ReactorContextTestExecutionListener();
		assertThat(comparator.compare(withSecurity, reactorContext)).isLessThan(0);
	}

	@Test
	public void checkSecurityContextResolutionWhenSubscribedContextCalledOnTheDifferentThreadThanWithSecurityContextTestExecutionListener() throws Exception {
		TestingAuthenticationToken contextHolder = new TestingAuthenticationToken("contextHolder", "password", "ROLE_USER");
		TestSecurityContextHolder.setAuthentication(contextHolder);

		this.listener.beforeTestMethod(this.testContext);

		ForkJoinPool.commonPool()
			.submit(() -> assertAuthentication(contextHolder))
			.join();
	}

	public void assertAuthentication(Authentication expected) {
		Mono<Authentication> authentication = ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication);

		StepVerifier.create(authentication)
			.expectNext(expected)
			.verifyComplete();
	}


	private void assertSecurityContext(SecurityContext expected) {
		Mono<SecurityContext> securityContext = ReactiveSecurityContextHolder.getContext();

		StepVerifier.create(securityContext)
			.expectNext(expected)
			.verifyComplete();
	}
}
