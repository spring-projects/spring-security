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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Supplier;
import java.util.stream.Stream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import org.springframework.aop.Pointcut;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory.TargetVisitor;
import org.springframework.security.authorization.method.AuthorizationProxy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class AuthorizationAdvisorProxyFactoryTests {

	private final Authentication user = TestAuthentication.authenticatedUser();

	private final Authentication admin = TestAuthentication.authenticatedAdmin();

	private final Flight flight = new Flight();

	private final User alan = new User("alan", "alan", "turing");

	@Test
	public void proxyWhenPreAuthorizeThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Flight flight = new Flight();
		assertThat(flight.getAltitude()).isEqualTo(35000d);
		Flight secured = proxy(factory, flight);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(secured::getAltitude);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeOnInterfaceThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		assertThat(this.alan.getFirstName()).isEqualTo("alan");
		User secured = proxy(factory, this.alan);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(secured::getFirstName);
		SecurityContextHolder.getContext().setAuthentication(authenticated("alan"));
		assertThat(secured.getFirstName()).isEqualTo("alan");
		SecurityContextHolder.getContext().setAuthentication(this.admin);
		assertThat(secured.getFirstName()).isEqualTo("alan");
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeOnRecordThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		HasSecret repo = new Repository("secret");
		assertThat(repo.secret()).isEqualTo("secret");
		HasSecret secured = proxy(factory, repo);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(secured::secret);
		SecurityContextHolder.getContext().setAuthentication(this.user);
		assertThat(repo.secret()).isEqualTo("secret");
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenImmutableListThenReturnsSecuredImmutableList() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		List<Flight> flights = List.of(this.flight);
		List<Flight> secured = proxy(factory, flights);
		secured.forEach(
				(flight) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(flight::getAltitude));
		assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(secured::clear);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenImmutableSetThenReturnsSecuredImmutableSet() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Set<Flight> flights = Set.of(this.flight);
		Set<Flight> secured = proxy(factory, flights);
		secured.forEach(
				(flight) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(flight::getAltitude));
		assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(secured::clear);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenQueueThenReturnsSecuredQueue() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Queue<Flight> flights = new LinkedList<>(List.of(this.flight));
		Queue<Flight> secured = proxy(factory, flights);
		assertThat(flights.size()).isEqualTo(secured.size());
		secured.forEach(
				(flight) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(flight::getAltitude));
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenImmutableSortedSetThenReturnsSecuredImmutableSortedSet() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		SortedSet<User> users = Collections.unmodifiableSortedSet(new TreeSet<>(Set.of(this.alan)));
		SortedSet<User> secured = proxy(factory, users);
		secured
			.forEach((user) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(user::getFirstName));
		assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(secured::clear);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenImmutableSortedMapThenReturnsSecuredImmutableSortedMap() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		SortedMap<String, User> users = Collections
			.unmodifiableSortedMap(new TreeMap<>(Map.of(this.alan.getId(), this.alan)));
		SortedMap<String, User> secured = proxy(factory, users);
		secured.forEach(
				(id, user) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(user::getFirstName));
		assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(secured::clear);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenImmutableMapThenReturnsSecuredImmutableMap() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Map<String, User> users = Map.of(this.alan.getId(), this.alan);
		Map<String, User> secured = proxy(factory, users);
		secured.forEach(
				(id, user) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(user::getFirstName));
		assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(secured::clear);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenMutableListThenReturnsSecuredMutableList() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		List<Flight> flights = new ArrayList<>(List.of(this.flight));
		List<Flight> secured = proxy(factory, flights);
		secured.forEach(
				(flight) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(flight::getAltitude));
		secured.clear();
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenMutableSetThenReturnsSecuredMutableSet() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Set<Flight> flights = new HashSet<>(Set.of(this.flight));
		Set<Flight> secured = proxy(factory, flights);
		secured.forEach(
				(flight) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(flight::getAltitude));
		secured.clear();
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenMutableSortedSetThenReturnsSecuredMutableSortedSet() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		SortedSet<User> users = new TreeSet<>(Set.of(this.alan));
		SortedSet<User> secured = proxy(factory, users);
		secured.forEach((u) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(u::getFirstName));
		secured.clear();
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenMutableSortedMapThenReturnsSecuredMutableSortedMap() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		SortedMap<String, User> users = new TreeMap<>(Map.of(this.alan.getId(), this.alan));
		SortedMap<String, User> secured = proxy(factory, users);
		secured.forEach((id, u) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(u::getFirstName));
		secured.clear();
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenMutableMapThenReturnsSecuredMutableMap() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Map<String, User> users = new HashMap<>(Map.of(this.alan.getId(), this.alan));
		Map<String, User> secured = proxy(factory, users);
		secured.forEach((id, u) -> assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(u::getFirstName));
		secured.clear();
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeForOptionalThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Optional<Flight> flights = Optional.of(this.flight);
		assertThat(flights.get().getAltitude()).isEqualTo(35000d);
		Optional<Flight> secured = proxy(factory, flights);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> secured.ifPresent(Flight::getAltitude));
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeForSupplierThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Supplier<Flight> flights = () -> this.flight;
		assertThat(flights.get().getAltitude()).isEqualTo(35000d);
		Supplier<Flight> secured = proxy(factory, flights);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> secured.get().getAltitude());
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeForStreamThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Stream<Flight> flights = Stream.of(this.flight);
		Stream<Flight> secured = proxy(factory, flights);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> secured.forEach(Flight::getAltitude));
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeForArrayThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Flight[] flights = { this.flight };
		Flight[] secured = proxy(factory, flights);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(secured[0]::getAltitude);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeForIteratorThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Iterator<Flight> flights = List.of(this.flight).iterator();
		Iterator<Flight> secured = proxy(factory, flights);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> secured.next().getAltitude());
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeForIterableThenHonors() {
		SecurityContextHolder.getContext().setAuthentication(this.user);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Iterable<User> users = new UserRepository();
		Iterable<User> secured = proxy(factory, users);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> secured.forEach(User::getFirstName));
		SecurityContextHolder.clearContext();
	}

	@Test
	public void proxyWhenPreAuthorizeForClassThenHonors() {
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Class<Flight> clazz = proxy(factory, Flight.class);
		assertThat(clazz.getSimpleName()).contains("SpringCGLIB$$");
		Flight secured = proxy(factory, this.flight);
		assertThat(secured.getClass()).isSameAs(clazz);
		SecurityContextHolder.getContext().setAuthentication(this.user);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(secured::getAltitude);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void setAdvisorsWhenProxyThenVisits() {
		AuthorizationAdvisor advisor = mock(AuthorizationAdvisor.class);
		given(advisor.getAdvice()).willReturn(advisor);
		given(advisor.getPointcut()).willReturn(Pointcut.TRUE);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		factory.setAdvisors(advisor);
		Flight flight = proxy(factory, this.flight);
		flight.getAltitude();
		verify(advisor, atLeastOnce()).getPointcut();
	}

	@Test
	public void setTargetVisitorThenUses() {
		TargetVisitor visitor = mock(TargetVisitor.class);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		factory.setTargetVisitor(visitor);
		factory.proxy(new Flight());
		verify(visitor).visit(any(), any());
	}

	@Test
	public void setTargetVisitorIgnoreValueTypesThenIgnores() {
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		assertThatExceptionOfType(ClassCastException.class).isThrownBy(() -> ((Integer) factory.proxy(35)).intValue());
		factory.setTargetVisitor(TargetVisitor.defaultsSkipValueTypes());
		assertThat(factory.proxy(35)).isEqualTo(35);
	}

	@Test
	public void serializeWhenAuthorizationProxyObjectThenOnlyIncludesProxiedProperties()
			throws JsonProcessingException {
		SecurityContextHolder.getContext().setAuthentication(this.admin);
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		User user = proxy(factory, this.alan);
		ObjectMapper mapper = new ObjectMapper();
		String serialized = mapper.writeValueAsString(user);
		Map<String, Object> properties = mapper.readValue(serialized, Map.class);
		assertThat(properties).hasSize(3).containsKeys("id", "firstName", "lastName");
	}

	@Test
	public void proxyWhenDefaultsThenInstanceOfAuthorizationProxy() {
		AuthorizationAdvisorProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
		Flight flight = proxy(factory, this.flight);
		assertThat(flight).isInstanceOf(AuthorizationProxy.class);
		Flight target = (Flight) ((AuthorizationProxy) flight).toAuthorizedTarget();
		assertThat(target).isSameAs(this.flight);
	}

	private Authentication authenticated(String user, String... authorities) {
		return TestAuthentication.authenticated(TestAuthentication.withUsername(user).authorities(authorities).build());
	}

	private <T> T proxy(AuthorizationProxyFactory factory, Object target) {
		return (T) factory.proxy(target);
	}

	static class Flight {

		@PreAuthorize("hasRole('PILOT')")
		Double getAltitude() {
			return 35000d;
		}

	}

	interface Identifiable {

		@PreAuthorize("authentication.name == this.id || hasRole('ADMIN')")
		String getFirstName();

		@PreAuthorize("authentication.name == this.id || hasRole('ADMIN')")
		String getLastName();

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
		public String getFirstName() {
			return this.firstName;
		}

		@Override
		public String getLastName() {
			return this.lastName;
		}

		@Override
		public int compareTo(@NotNull User that) {
			return this.id.compareTo(that.getId());
		}

	}

	static class UserRepository implements Iterable<User> {

		List<User> users = List.of(new User("1", "first", "last"));

		@NotNull
		@Override
		public Iterator<User> iterator() {
			return this.users.iterator();
		}

	}

	interface HasSecret {

		String secret();

	}

	record Repository(@PreAuthorize("hasRole('ADMIN')") String secret) implements HasSecret {
	}

}
