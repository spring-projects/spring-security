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

package org.springframework.security.authorization;

import java.util.Iterator;
import java.util.List;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.aop.Pointcut;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class ReactiveAuthorizationAdvisorProxyFactoryTests {

	private final Authentication user = TestAuthentication.authenticatedUser();

	private final Authentication admin = TestAuthentication.authenticatedAdmin();

	private final Flight flight = new Flight();

	private final User alan = new User("alan", "alan", "turing");

	@Test
	public void proxyWhenPreAuthorizeThenHonors() {
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withReactiveDefaults();
		Flight flight = new Flight();
		StepVerifier
			.create(flight.getAltitude().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.user)))
			.expectNext(35000d)
			.verifyComplete();
		Flight secured = proxy(factory, flight);
		StepVerifier
			.create(secured.getAltitude().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.user)))
			.verifyError(AccessDeniedException.class);
	}

	@Test
	public void proxyWhenPreAuthorizeOnInterfaceThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withReactiveDefaults();
		StepVerifier
			.create(this.alan.getFirstName().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.user)))
			.expectNext("alan")
			.verifyComplete();
		User secured = proxy(factory, this.alan);
		StepVerifier
			.create(secured.getFirstName().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.user)))
			.verifyError(AccessDeniedException.class);
		StepVerifier
			.create(secured.getFirstName()
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authenticated("alan"))))
			.expectNext("alan")
			.verifyComplete();
		StepVerifier
			.create(secured.getFirstName().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.admin)))
			.expectNext("alan")
			.verifyComplete();
	}

	@Test
	public void proxyWhenPreAuthorizeOnRecordThenHonors() {
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withReactiveDefaults();
		HasSecret repo = new Repository(Mono.just("secret"));
		StepVerifier.create(repo.secret().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.user)))
			.expectNext("secret")
			.verifyComplete();
		HasSecret secured = proxy(factory, repo);
		StepVerifier.create(secured.secret().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.user)))
			.verifyError(AccessDeniedException.class);
		StepVerifier.create(secured.secret().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.admin)))
			.expectNext("secret")
			.verifyComplete();
	}

	@Test
	public void proxyWhenPreAuthorizeOnFluxThenHonors() {
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withReactiveDefaults();
		Flux<Flight> flights = Flux.just(this.flight);
		Flux<Flight> secured = proxy(factory, flights);
		StepVerifier
			.create(secured.flatMap(Flight::getAltitude)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.user)))
			.verifyError(AccessDeniedException.class);
	}

	@Test
	public void proxyWhenPreAuthorizeForClassThenHonors() {
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withReactiveDefaults();
		Class<Flight> clazz = proxy(factory, Flight.class);
		assertThat(clazz.getSimpleName()).contains("SpringCGLIB$$");
		Flight secured = proxy(factory, this.flight);
		StepVerifier
			.create(secured.getAltitude().contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.user)))
			.verifyError(AccessDeniedException.class);
	}

	@Test
	public void setAdvisorsWhenProxyThenVisits() {
		AuthorizationAdvisor advisor = mock(AuthorizationAdvisor.class);
		given(advisor.getAdvice()).willReturn(advisor);
		given(advisor.getPointcut()).willReturn(Pointcut.TRUE);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withReactiveDefaults();
		factory.setAdvisors(advisor);
		Flight flight = proxy(factory, this.flight);
		flight.getAltitude();
		verify(advisor, atLeastOnce()).getPointcut();
	}

	private Authentication authenticated(String user, String... authorities) {
		return TestAuthentication.authenticated(TestAuthentication.withUsername(user).authorities(authorities).build());
	}

	private <T> T proxy(AuthorizationProxyFactory factory, Object target) {
		return (T) factory.proxy(target);
	}

	static class Flight {

		@PreAuthorize("hasRole('PILOT')")
		Mono<Double> getAltitude() {
			return Mono.just(35000d);
		}

	}

	interface Identifiable {

		@PreAuthorize("authentication.name == this.id || hasRole('ADMIN')")
		Mono<String> getFirstName();

		@PreAuthorize("authentication.name == this.id || hasRole('ADMIN')")
		Mono<String> getLastName();

	}

	public static class User implements Identifiable, Comparable<User> {

		private final String id;

		private final String firstName;

		private final String lastName;

		User(String id, String firstName, String lastName) {
			this.id = id;
			this.firstName = firstName;
			this.lastName = lastName;
		}

		public String getId() {
			return this.id;
		}

		@Override
		public Mono<String> getFirstName() {
			return Mono.just(this.firstName);
		}

		@Override
		public Mono<String> getLastName() {
			return Mono.just(this.lastName);
		}

		@Override
		public int compareTo(@NotNull User that) {
			return this.id.compareTo(that.getId());
		}

	}

	static class UserRepository implements Iterable<User> {

		List<User> users = List.of(new User("1", "first", "last"));

		Flux<User> findAll() {
			return Flux.fromIterable(this.users);
		}

		@NotNull
		@Override
		public Iterator<User> iterator() {
			return this.users.iterator();
		}

	}

	interface HasSecret {

		Mono<String> secret();

	}

	record Repository(@PreAuthorize("hasRole('ADMIN')") Mono<String> secret) implements HasSecret {
	}

}
