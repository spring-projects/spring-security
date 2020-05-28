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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.TestPublisher;
import reactor.util.context.Context;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * @author Rob Winch
 * @author Sheiy
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@ContextConfiguration
public class EnableReactiveMethodSecurityTests {
	@Autowired ReactiveMessageService messageService;
	ReactiveMessageService delegate;
	TestPublisher<String> result = TestPublisher.create();

	Context withAdmin = ReactiveSecurityContextHolder.withAuthentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"));
	Context withUser = ReactiveSecurityContextHolder.withAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"));

	@After
	public void cleanup() {
		reset(delegate);
	}

	@Autowired
	public void setConfig(Config config) {
		this.delegate = config.delegate;
	}

	@Test
	public void notPublisherPreAuthorizeFindByIdThenThrowsIllegalStateException() {
		assertThatThrownBy(() -> this.messageService.notPublisherPreAuthorizeFindById(1L))
			.isInstanceOf(IllegalStateException.class)
			.extracting(Throwable::getMessage)
			.isEqualTo("The returnType class java.lang.String on public abstract java.lang.String org.springframework.security.config.annotation.method.configuration.ReactiveMessageService.notPublisherPreAuthorizeFindById(long) must return an instance of org.reactivestreams.Publisher (i.e. Mono / Flux) in order to support Reactor Context");
	}

	@Test
	public void monoWhenPermitAllThenAopDoesNotSubscribe() {
		when(this.delegate.monoFindById(1L)).thenReturn(Mono.from(result));

		this.delegate.monoFindById(1L);

		result.assertNoSubscribers();
	}

	@Test
	public void monoWhenPermitAllThenSuccess() {
		when(this.delegate.monoFindById(1L)).thenReturn(Mono.just("success"));

		StepVerifier.create(this.delegate.monoFindById(1L))
			.expectNext("success")
			.verifyComplete();
	}

	@Test
	public void monoPreAuthorizeHasRoleWhenGrantedThenSuccess() {
		when(this.delegate.monoPreAuthorizeHasRoleFindById(1L)).thenReturn(Mono.just("result"));

		Mono<String> findById = this.messageService.monoPreAuthorizeHasRoleFindById(1L)
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void monoPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
		when(this.delegate.monoPreAuthorizeHasRoleFindById(1L)).thenReturn(Mono.from(result));

		Mono<String> findById = this.messageService.monoPreAuthorizeHasRoleFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void monoPreAuthorizeHasRoleWhenNotAuthorizedThenDenied() {
		when(this.delegate.monoPreAuthorizeHasRoleFindById(1L)).thenReturn(Mono.from(result));

		Mono<String> findById = this.messageService.monoPreAuthorizeHasRoleFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void monoPreAuthorizeBeanWhenGrantedThenSuccess() {
		when(this.delegate.monoPreAuthorizeBeanFindById(2L)).thenReturn(Mono.just("result"));

		Mono<String> findById = this.messageService.monoPreAuthorizeBeanFindById(2L)
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void monoPreAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		when(this.delegate.monoPreAuthorizeBeanFindById(2L)).thenReturn(Mono.just("result"));

		Mono<String> findById = this.messageService.monoPreAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void monoPreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		when(this.delegate.monoPreAuthorizeBeanFindById(1L)).thenReturn(Mono.from(result));

		Mono<String> findById = this.messageService.monoPreAuthorizeBeanFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void monoPreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		when(this.delegate.monoPreAuthorizeBeanFindById(1L)).thenReturn(Mono.from(result));

		Mono<String> findById = this.messageService.monoPreAuthorizeBeanFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void monoReactivePreAuthorizeBeanWhenGrantedThenSuccess() {
		when(this.delegate.monoReactivePreAuthorizeBeanFindById(2L)).thenReturn(Mono.just("result"));

		Mono<String> findById = this.messageService.monoReactivePreAuthorizeBeanFindById(2L)
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void monoReactivePreAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		when(this.delegate.monoReactivePreAuthorizeBeanFindById(2L)).thenReturn(Mono.just("result"));

		Mono<String> findById = this.messageService.monoReactivePreAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void monoReactivePreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		when(this.delegate.monoReactivePreAuthorizeBeanFindById(1L)).thenReturn(Mono.from(result));

		Mono<String> findById = this.messageService.monoReactivePreAuthorizeBeanFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void monoReactivePreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		when(this.delegate.monoReactivePreAuthorizeBeanFindById(1L)).thenReturn(Mono.from(result));

		Mono<String> findById = this.messageService.monoReactivePreAuthorizeBeanFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void monoPostAuthorizeWhenAuthorizedThenSuccess() {
		when(this.delegate.monoPostAuthorizeFindById(1L)).thenReturn(Mono.just("user"));

		Mono<String> findById = this.messageService.monoPostAuthorizeFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectNext("user")
				.verifyComplete();
	}

	@Test
	public void monoPostAuthorizeWhenNotAuthorizedThenDenied() {
		when(this.delegate.monoPostAuthorizeBeanFindById(1L)).thenReturn(Mono.just("not-authorized"));

		Mono<String> findById = this.messageService.monoPostAuthorizeBeanFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	@Test
	public void monoPostAuthorizeWhenBeanAndAuthorizedThenSuccess() {
		when(this.delegate.monoPostAuthorizeBeanFindById(2L)).thenReturn(Mono.just("user"));

		Mono<String> findById = this.messageService.monoPostAuthorizeBeanFindById(2L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectNext("user")
				.verifyComplete();
	}

	@Test
	public void monoPostAuthorizeWhenBeanAndNotAuthenticatedAndAuthorizedThenSuccess() {
		when(this.delegate.monoPostAuthorizeBeanFindById(2L)).thenReturn(Mono.just("anonymous"));

		Mono<String> findById = this.messageService.monoPostAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("anonymous")
				.verifyComplete();
	}

	@Test
	public void monoPostAuthorizeWhenBeanAndNotAuthorizedThenDenied() {
		when(this.delegate.monoPostAuthorizeBeanFindById(1L)).thenReturn(Mono.just("not-authorized"));

		Mono<String> findById = this.messageService.monoPostAuthorizeBeanFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	// Flux tests

	@Test
	public void fluxWhenPermitAllThenAopDoesNotSubscribe() {
		when(this.delegate.fluxFindById(1L)).thenReturn(Flux.from(result));

		this.delegate.fluxFindById(1L);

		result.assertNoSubscribers();
	}

	@Test
	public void fluxWhenPermitAllThenSuccess() {
		when(this.delegate.fluxFindById(1L)).thenReturn(Flux.just("success"));

		StepVerifier.create(this.delegate.fluxFindById(1L))
				.expectNext("success")
				.verifyComplete();
	}

	@Test
	public void fluxPreAuthorizeHasRoleWhenGrantedThenSuccess() {
		when(this.delegate.fluxPreAuthorizeHasRoleFindById(1L)).thenReturn(Flux.just("result"));

		Flux<String> findById = this.messageService.fluxPreAuthorizeHasRoleFindById(1L)
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.consumeNextWith( s -> AssertionsForClassTypes.assertThat(s).isEqualTo("result"))
				.verifyComplete();
	}

	@Test
	public void fluxPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
		when(this.delegate.fluxPreAuthorizeHasRoleFindById(1L)).thenReturn(Flux.from(result));

		Flux<String> findById = this.messageService.fluxPreAuthorizeHasRoleFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void fluxPreAuthorizeHasRoleWhenNotAuthorizedThenDenied() {
		when(this.delegate.fluxPreAuthorizeHasRoleFindById(1L)).thenReturn(Flux.from(result));

		Flux<String> findById = this.messageService.fluxPreAuthorizeHasRoleFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void fluxPreAuthorizeBeanWhenGrantedThenSuccess() {
		when(this.delegate.fluxPreAuthorizeBeanFindById(2L)).thenReturn(Flux.just("result"));

		Flux<String> findById = this.messageService.fluxPreAuthorizeBeanFindById(2L)
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void fluxPreAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		when(this.delegate.fluxPreAuthorizeBeanFindById(2L)).thenReturn(Flux.just("result"));

		Flux<String> findById = this.messageService.fluxPreAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void fluxPreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		when(this.delegate.fluxPreAuthorizeBeanFindById(1L)).thenReturn(Flux.from(result));

		Flux<String> findById = this.messageService.fluxPreAuthorizeBeanFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void fluxPreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		when(this.delegate.fluxPreAuthorizeBeanFindById(1L)).thenReturn(Flux.from(result));

		Flux<String> findById = this.messageService.fluxPreAuthorizeBeanFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void fluxReactivePreAuthorizeBeanWhenGrantedThenSuccess() {
		when(this.delegate.fluxReactivePreAuthorizeBeanFindById(2L)).thenReturn(Flux.just("result"));

		Flux<String> findById = this.messageService.fluxReactivePreAuthorizeBeanFindById(2L)
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void fluxPreReactiveAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		when(this.delegate.fluxReactivePreAuthorizeBeanFindById(2L)).thenReturn(Flux.just("result"));

		Flux<String> findById = this.messageService.fluxReactivePreAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void fluxReactivePreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		when(this.delegate.fluxReactivePreAuthorizeBeanFindById(1L)).thenReturn(Flux.from(result));

		Flux<String> findById = this.messageService.fluxReactivePreAuthorizeBeanFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void fluxReactivePreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		when(this.delegate.fluxReactivePreAuthorizeBeanFindById(1L)).thenReturn(Flux.from(result));

		Flux<String> findById = this.messageService.fluxReactivePreAuthorizeBeanFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void fluxPostAuthorizeWhenAuthorizedThenSuccess() {
		when(this.delegate.fluxPostAuthorizeFindById(1L)).thenReturn(Flux.just("user"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectNext("user")
				.verifyComplete();
	}

	@Test
	public void fluxPostAuthorizeWhenNotAuthorizedThenDenied() {
		when(this.delegate.fluxPostAuthorizeBeanFindById(1L)).thenReturn(Flux.just("not-authorized"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeBeanFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	@Test
	public void fluxPostAuthorizeWhenBeanAndAuthorizedThenSuccess() {
		when(this.delegate.fluxPostAuthorizeBeanFindById(2L)).thenReturn(Flux.just("user"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeBeanFindById(2L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectNext("user")
				.verifyComplete();
	}

	@Test
	public void fluxPostAuthorizeWhenBeanAndNotAuthenticatedAndAuthorizedThenSuccess() {
		when(this.delegate.fluxPostAuthorizeBeanFindById(2L)).thenReturn(Flux.just("anonymous"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("anonymous")
				.verifyComplete();
	}

	@Test
	public void fluxPostAuthorizeWhenBeanAndNotAuthorizedThenDenied() {
		when(this.delegate.fluxPostAuthorizeBeanFindById(1L)).thenReturn(Flux.just("not-authorized"));

		Flux<String> findById = this.messageService.fluxPostAuthorizeBeanFindById(1L)
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	// Publisher tests

	@Test
	public void publisherWhenPermitAllThenAopDoesNotSubscribe() {
		when(this.delegate.publisherFindById(1L)).thenReturn(result);

		this.delegate.publisherFindById(1L);

		result.assertNoSubscribers();
	}

	@Test
	public void publisherWhenPermitAllThenSuccess() {
		when(this.delegate.publisherFindById(1L)).thenReturn(publisherJust("success"));

		StepVerifier.create(this.delegate.publisherFindById(1L))
				.expectNext("success")
				.verifyComplete();
	}

	@Test
	public void publisherPreAuthorizeHasRoleWhenGrantedThenSuccess() {
		when(this.delegate.publisherPreAuthorizeHasRoleFindById(1L)).thenReturn(publisherJust("result"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPreAuthorizeHasRoleFindById(1L))
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.consumeNextWith( s -> AssertionsForClassTypes.assertThat(s).isEqualTo("result"))
				.verifyComplete();
	}

	@Test
	public void publisherPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
		when(this.delegate.publisherPreAuthorizeHasRoleFindById(1L)).thenReturn(result);

		Publisher<String> findById = this.messageService.publisherPreAuthorizeHasRoleFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void publisherPreAuthorizeHasRoleWhenNotAuthorizedThenDenied() {
		when(this.delegate.publisherPreAuthorizeHasRoleFindById(1L)).thenReturn(result);

		Publisher<String> findById = Flux.from(this.messageService.publisherPreAuthorizeHasRoleFindById(1L))
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void publisherPreAuthorizeBeanWhenGrantedThenSuccess() {
		when(this.delegate.publisherPreAuthorizeBeanFindById(2L)).thenReturn(publisherJust("result"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPreAuthorizeBeanFindById(2L))
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void publisherPreAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		when(this.delegate.publisherPreAuthorizeBeanFindById(2L)).thenReturn(publisherJust("result"));

		Publisher<String> findById = this.messageService.publisherPreAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void publisherPreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		when(this.delegate.publisherPreAuthorizeBeanFindById(1L)).thenReturn(result);

		Publisher<String> findById = this.messageService.publisherPreAuthorizeBeanFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void publisherPreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		when(this.delegate.publisherPreAuthorizeBeanFindById(1L)).thenReturn(result);

		Publisher<String> findById = Flux.from(this.messageService.publisherPreAuthorizeBeanFindById(1L))
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void publisherReactivePreAuthorizeBeanWhenGrantedThenSuccess() {
		when(this.delegate.publisherReactivePreAuthorizeBeanFindById(2L)).thenReturn(publisherJust("result"));

		Publisher<String> findById = Flux.from(this.messageService.publisherReactivePreAuthorizeBeanFindById(2L))
				.subscriberContext(withAdmin);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void publisherReactivePreAuthorizeBeanWhenNotAuthenticatedAndGrantedThenSuccess() {
		when(this.delegate.publisherReactivePreAuthorizeBeanFindById(2L)).thenReturn(publisherJust("result"));

		Publisher<String> findById = this.messageService.publisherReactivePreAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("result")
				.verifyComplete();
	}

	@Test
	public void publisherReactivePreAuthorizeBeanWhenNoAuthenticationThenDenied() {
		when(this.delegate.publisherReactivePreAuthorizeBeanFindById(1L)).thenReturn(result);

		Publisher<String> findById = this.messageService.publisherReactivePreAuthorizeBeanFindById(1L);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void publisherReactivePreAuthorizeBeanWhenNotAuthorizedThenDenied() {
		when(this.delegate.publisherReactivePreAuthorizeBeanFindById(1L)).thenReturn(result);

		Publisher<String> findById = Flux.from(this.messageService.publisherReactivePreAuthorizeBeanFindById(1L))
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();

		result.assertNoSubscribers();
	}

	@Test
	public void publisherPostAuthorizeWhenAuthorizedThenSuccess() {
		when(this.delegate.publisherPostAuthorizeFindById(1L)).thenReturn(publisherJust("user"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPostAuthorizeFindById(1L))
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectNext("user")
				.verifyComplete();
	}

	@Test
	public void publisherPostAuthorizeWhenNotAuthorizedThenDenied() {
		when(this.delegate.publisherPostAuthorizeBeanFindById(1L)).thenReturn(publisherJust("not-authorized"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPostAuthorizeBeanFindById(1L))
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	@Test
	public void publisherPostAuthorizeWhenBeanAndAuthorizedThenSuccess() {
		when(this.delegate.publisherPostAuthorizeBeanFindById(2L)).thenReturn(publisherJust("user"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPostAuthorizeBeanFindById(2L))
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectNext("user")
				.verifyComplete();
	}

	@Test
	public void publisherPostAuthorizeWhenBeanAndNotAuthenticatedAndAuthorizedThenSuccess() {
		when(this.delegate.publisherPostAuthorizeBeanFindById(2L)).thenReturn(publisherJust("anonymous"));

		Publisher<String> findById = this.messageService.publisherPostAuthorizeBeanFindById(2L);
		StepVerifier
				.create(findById)
				.expectNext("anonymous")
				.verifyComplete();
	}

	@Test
	public void publisherPostAuthorizeWhenBeanAndNotAuthorizedThenDenied() {
		when(this.delegate.publisherPostAuthorizeBeanFindById(1L)).thenReturn(publisherJust("not-authorized"));

		Publisher<String> findById = Flux.from(this.messageService.publisherPostAuthorizeBeanFindById(1L))
				.subscriberContext(withUser);
		StepVerifier
				.create(findById)
				.expectError(AccessDeniedException.class)
				.verify();
	}

	static <T> Publisher<T> publisher(Flux<T> flux) {
		return subscriber -> flux.subscribe(subscriber);
	}

	static <T> Publisher<T> publisherJust(T... data) {
		return publisher(Flux.just(data));
	}

	@EnableReactiveMethodSecurity
	static class Config {
		ReactiveMessageService delegate = mock(ReactiveMessageService.class);

		@Bean
		public DelegatingReactiveMessageService defaultMessageService() {
			return new DelegatingReactiveMessageService(delegate);
		}

		@Bean
		public Authz authz() {
			return new Authz();
		}
	}
}
