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

package org.springframework.security.config.annotation.method.configuration;

import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.TestPublisher;
import reactor.util.context.Context;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@ContextConfiguration
public class EnableReactiveMethodSecurityTests {

	@Autowired
	ReactiveMessageService messageService;

	ReactiveMessageService delegate;

	TestPublisher<String> result = TestPublisher.create();

	Context withAdmin = ReactiveSecurityContextHolder
			.withAuthentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"));

	Context withUser = ReactiveSecurityContextHolder
			.withAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"));

	@After
	public void cleanup() {
		reset(this.delegate);
	}

	@Autowired
	public void setConfig(Config config) {
		this.delegate = config.delegate;
	}

	@Test
	public void notPublisherPreAuthorizeFindByIdThenThrowsIllegalStateException() {
		assertThatThrownBy(() -> this.messageService.notPublisherPreAuthorizeFindById(1L))
				.isInstanceOf(IllegalStateException.class).extracting(Throwable::getMessage).isEqualTo(
						"The returnType class java.lang.String on public abstract java.lang.String org.springframework.security.config.annotation.method.configuration.ReactiveMessageService.notPublisherPreAuthorizeFindById(long) must return an instance of org.reactivestreams.Publisher (i.e. Mono / Flux) in order to support Reactor Context");
	}

	@Test
	public void monoWhenPermitAllThenAopDoesNotSubscribe() {
		given(this.delegate.monoFindById(1L)).willReturn(Mono.from(this.result));

		this.delegate.monoFindById(1L);

		this.result.assertNoSubscribers();
	}

	@Test
	public void monoWhenPermitAllThenSuccess() {
		given(this.delegate.monoFindById(1L)).willReturn(Mono.just("success"));

		StepVerifier.create(this.delegate.monoFindById(1L)).expectNext("success").verifyComplete();
	}

	@Test
	public void monoPreAuthorizeHasRoleWhenGrantedThenSuccess() {
		given(this.delegate.monoPreAuthorizeHasRoleFindById(1L)).willReturn(Mono.just("result"));

		Mono<String> findById = this.messageService.monoPreAuthorizeHasRoleFindById(1L)
				.subscriberContext(this.withAdmin);
		StepVerifier.create(findById).expectNext("result").verifyComplete();
	}

	@Test
	public void monoPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
		given(this.delegate.monoPreAuthorizeHasRoleFindById(1L)).willReturn(Mono.from(this.result));

		Mono<String> findById = this.messageService.monoPreAuthorizeHasRoleFindById(1L);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void monoPreAuthorizeHasRoleWhenNotAuthorizedThenDenied() {
		given(this.delegate.monoPreAuthorizeHasRoleFindById(1L)).willReturn(Mono.from(this.result));

		Mono<String> findById = this.messageService.monoPreAuthorizeHasRoleFindById(1L)
				.subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void monoPreAuthorizeBeanWhenGrantedThenSuccess() {
		given(this.delegate.monoPreAuthorizeBeanFindById(2L)).willReturn(Mono.just("result"));

		Mono<String> findById = this.messageService.monoPreAuthorizeBeanFindById(2L).subscriberContext(this.withAdmin);
		StepVerifier.create(findById).expectNext("result").verifyComplete();
	}

	@Test
	public void monoPreAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		given(this.delegate.monoPreAuthorizeBeanFindById(2L)).willReturn(Mono.just("result"));

		Mono<String> findById = this.messageService.monoPreAuthorizeBeanFindById(2L);
		StepVerifier.create(findById).expectNext("result").verifyComplete();
	}

	@Test
	public void monoPreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		given(this.delegate.monoPreAuthorizeBeanFindById(1L)).willReturn(Mono.from(this.result));

		Mono<String> findById = this.messageService.monoPreAuthorizeBeanFindById(1L);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void monoPreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		given(this.delegate.monoPreAuthorizeBeanFindById(1L)).willReturn(Mono.from(this.result));

		Mono<String> findById = this.messageService.monoPreAuthorizeBeanFindById(1L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void monoPostAuthorizeWhenAuthorizedThenSuccess() {
		given(this.delegate.monoPostAuthorizeFindById(1L)).willReturn(Mono.just("user"));

		Mono<String> findById = this.messageService.monoPostAuthorizeFindById(1L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectNext("user").verifyComplete();
	}

	@Test
	public void monoPostAuthorizeWhenNotAuthorizedThenDenied() {
		given(this.delegate.monoPostAuthorizeBeanFindById(1L)).willReturn(Mono.just("not-authorized"));

		Mono<String> findById = this.messageService.monoPostAuthorizeBeanFindById(1L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();
	}

	@Test
	public void monoPostAuthorizeWhenBeanAndAuthorizedThenSuccess() {
		given(this.delegate.monoPostAuthorizeBeanFindById(2L)).willReturn(Mono.just("user"));

		Mono<String> findById = this.messageService.monoPostAuthorizeBeanFindById(2L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectNext("user").verifyComplete();
	}

	@Test
	public void monoPostAuthorizeWhenBeanAndNotAuthenticatedAndAuthorizedThenSuccess() {
		given(this.delegate.monoPostAuthorizeBeanFindById(2L)).willReturn(Mono.just("anonymous"));

		Mono<String> findById = this.messageService.monoPostAuthorizeBeanFindById(2L);
		StepVerifier.create(findById).expectNext("anonymous").verifyComplete();
	}

	@Test
	public void monoPostAuthorizeWhenBeanAndNotAuthorizedThenDenied() {
		given(this.delegate.monoPostAuthorizeBeanFindById(1L)).willReturn(Mono.just("not-authorized"));

		Mono<String> findById = this.messageService.monoPostAuthorizeBeanFindById(1L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();
	}

	// Flux tests

	@Test
	public void fluxWhenPermitAllThenAopDoesNotSubscribe() {
		given(this.delegate.fluxFindById(1L)).willReturn(Flux.from(this.result));

		this.delegate.fluxFindById(1L);

		this.result.assertNoSubscribers();
	}

	@Test
	public void fluxWhenPermitAllThenSuccess() {
		given(this.delegate.fluxFindById(1L)).willReturn(Flux.just("success"));

		StepVerifier.create(this.delegate.fluxFindById(1L)).expectNext("success").verifyComplete();
	}

	@Test
	public void fluxPreAuthorizeHasRoleWhenGrantedThenSuccess() {
		given(this.delegate.fluxPreAuthorizeHasRoleFindById(1L)).willReturn(Flux.just("result"));

		Flux<String> findById = this.messageService.fluxPreAuthorizeHasRoleFindById(1L)
				.subscriberContext(this.withAdmin);
		StepVerifier.create(findById).consumeNextWith((s) -> AssertionsForClassTypes.assertThat(s).isEqualTo("result"))
				.verifyComplete();
	}

	@Test
	public void fluxPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
		given(this.delegate.fluxPreAuthorizeHasRoleFindById(1L)).willReturn(Flux.from(this.result));

		Flux<String> findById = this.messageService.fluxPreAuthorizeHasRoleFindById(1L);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void fluxPreAuthorizeHasRoleWhenNotAuthorizedThenDenied() {
		given(this.delegate.fluxPreAuthorizeHasRoleFindById(1L)).willReturn(Flux.from(this.result));

		Flux<String> findById = this.messageService.fluxPreAuthorizeHasRoleFindById(1L)
				.subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void fluxPreAuthorizeBeanWhenGrantedThenSuccess() {
		given(this.delegate.fluxPreAuthorizeBeanFindById(2L)).willReturn(Flux.just("result"));

		Flux<String> findById = this.messageService.fluxPreAuthorizeBeanFindById(2L).subscriberContext(this.withAdmin);
		StepVerifier.create(findById).expectNext("result").verifyComplete();
	}

	@Test
	public void fluxPreAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		given(this.delegate.fluxPreAuthorizeBeanFindById(2L)).willReturn(Flux.just("result"));

		Flux<String> findById = this.messageService.fluxPreAuthorizeBeanFindById(2L);
		StepVerifier.create(findById).expectNext("result").verifyComplete();
	}

	@Test
	public void fluxPreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		given(this.delegate.fluxPreAuthorizeBeanFindById(1L)).willReturn(Flux.from(this.result));

		Flux<String> findById = this.messageService.fluxPreAuthorizeBeanFindById(1L);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void fluxPreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		given(this.delegate.fluxPreAuthorizeBeanFindById(1L)).willReturn(Flux.from(this.result));

		Flux<String> findById = this.messageService.fluxPreAuthorizeBeanFindById(1L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void fluxPostAuthorizeWhenAuthorizedThenSuccess() {
		given(this.delegate.fluxPostAuthorizeFindById(1L)).willReturn(Flux.just("user"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeFindById(1L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectNext("user").verifyComplete();
	}

	@Test
	public void fluxPostAuthorizeWhenNotAuthorizedThenDenied() {
		given(this.delegate.fluxPostAuthorizeBeanFindById(1L)).willReturn(Flux.just("not-authorized"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeBeanFindById(1L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();
	}

	@Test
	public void fluxPostAuthorizeWhenBeanAndAuthorizedThenSuccess() {
		given(this.delegate.fluxPostAuthorizeBeanFindById(2L)).willReturn(Flux.just("user"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeBeanFindById(2L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectNext("user").verifyComplete();
	}

	@Test
	public void fluxPostAuthorizeWhenBeanAndNotAuthenticatedAndAuthorizedThenSuccess() {
		given(this.delegate.fluxPostAuthorizeBeanFindById(2L)).willReturn(Flux.just("anonymous"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeBeanFindById(2L);
		StepVerifier.create(findById).expectNext("anonymous").verifyComplete();
	}

	@Test
	public void fluxPostAuthorizeWhenBeanAndNotAuthorizedThenDenied() {
		given(this.delegate.fluxPostAuthorizeBeanFindById(1L)).willReturn(Flux.just("not-authorized"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeBeanFindById(1L).subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();
	}

	// Publisher tests

	@Test
	public void publisherWhenPermitAllThenAopDoesNotSubscribe() {
		given(this.delegate.publisherFindById(1L)).willReturn(this.result);

		this.delegate.publisherFindById(1L);

		this.result.assertNoSubscribers();
	}

	@Test
	public void publisherWhenPermitAllThenSuccess() {
		given(this.delegate.publisherFindById(1L)).willReturn(publisherJust("success"));

		StepVerifier.create(this.delegate.publisherFindById(1L)).expectNext("success").verifyComplete();
	}

	@Test
	public void publisherPreAuthorizeHasRoleWhenGrantedThenSuccess() {
		given(this.delegate.publisherPreAuthorizeHasRoleFindById(1L)).willReturn(publisherJust("result"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPreAuthorizeHasRoleFindById(1L))
				.subscriberContext(this.withAdmin);
		StepVerifier.create(findById).consumeNextWith((s) -> AssertionsForClassTypes.assertThat(s).isEqualTo("result"))
				.verifyComplete();
	}

	@Test
	public void publisherPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
		given(this.delegate.publisherPreAuthorizeHasRoleFindById(1L)).willReturn(this.result);

		Publisher<String> findById = this.messageService.publisherPreAuthorizeHasRoleFindById(1L);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void publisherPreAuthorizeHasRoleWhenNotAuthorizedThenDenied() {
		given(this.delegate.publisherPreAuthorizeHasRoleFindById(1L)).willReturn(this.result);

		Publisher<String> findById = Flux.from(this.messageService.publisherPreAuthorizeHasRoleFindById(1L))
				.subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void publisherPreAuthorizeBeanWhenGrantedThenSuccess() {
		given(this.delegate.publisherPreAuthorizeBeanFindById(2L)).willReturn(publisherJust("result"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPreAuthorizeBeanFindById(2L))
				.subscriberContext(this.withAdmin);
		StepVerifier.create(findById).expectNext("result").verifyComplete();
	}

	@Test
	public void publisherPreAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		given(this.delegate.publisherPreAuthorizeBeanFindById(2L)).willReturn(publisherJust("result"));

		Publisher<String> findById = this.messageService.publisherPreAuthorizeBeanFindById(2L);
		StepVerifier.create(findById).expectNext("result").verifyComplete();
	}

	@Test
	public void publisherPreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		given(this.delegate.publisherPreAuthorizeBeanFindById(1L)).willReturn(this.result);

		Publisher<String> findById = this.messageService.publisherPreAuthorizeBeanFindById(1L);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void publisherPreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		given(this.delegate.publisherPreAuthorizeBeanFindById(1L)).willReturn(this.result);

		Publisher<String> findById = Flux.from(this.messageService.publisherPreAuthorizeBeanFindById(1L))
				.subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();

		this.result.assertNoSubscribers();
	}

	@Test
	public void publisherPostAuthorizeWhenAuthorizedThenSuccess() {
		given(this.delegate.publisherPostAuthorizeFindById(1L)).willReturn(publisherJust("user"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPostAuthorizeFindById(1L))
				.subscriberContext(this.withUser);
		StepVerifier.create(findById).expectNext("user").verifyComplete();
	}

	@Test
	public void publisherPostAuthorizeWhenNotAuthorizedThenDenied() {
		given(this.delegate.publisherPostAuthorizeBeanFindById(1L)).willReturn(publisherJust("not-authorized"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPostAuthorizeBeanFindById(1L))
				.subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();
	}

	@Test
	public void publisherPostAuthorizeWhenBeanAndAuthorizedThenSuccess() {
		given(this.delegate.publisherPostAuthorizeBeanFindById(2L)).willReturn(publisherJust("user"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPostAuthorizeBeanFindById(2L))
				.subscriberContext(this.withUser);
		StepVerifier.create(findById).expectNext("user").verifyComplete();
	}

	@Test
	public void publisherPostAuthorizeWhenBeanAndNotAuthenticatedAndAuthorizedThenSuccess() {
		given(this.delegate.publisherPostAuthorizeBeanFindById(2L)).willReturn(publisherJust("anonymous"));

		Publisher<String> findById = this.messageService.publisherPostAuthorizeBeanFindById(2L);
		StepVerifier.create(findById).expectNext("anonymous").verifyComplete();
	}

	@Test
	public void publisherPostAuthorizeWhenBeanAndNotAuthorizedThenDenied() {
		given(this.delegate.publisherPostAuthorizeBeanFindById(1L)).willReturn(publisherJust("not-authorized"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPostAuthorizeBeanFindById(1L))
				.subscriberContext(this.withUser);
		StepVerifier.create(findById).expectError(AccessDeniedException.class).verify();
	}

	static <T> Publisher<T> publisher(Flux<T> flux) {
		return (subscriber) -> flux.subscribe(subscriber);
	}

	static <T> Publisher<T> publisherJust(T... data) {
		return publisher(Flux.just(data));
	}

	@EnableReactiveMethodSecurity
	static class Config {

		ReactiveMessageService delegate = mock(ReactiveMessageService.class);

		@Bean
		DelegatingReactiveMessageService defaultMessageService() {
			return new DelegatingReactiveMessageService(this.delegate);
		}

		@Bean
		Authz authz() {
			return new Authz();
		}

	}

}
