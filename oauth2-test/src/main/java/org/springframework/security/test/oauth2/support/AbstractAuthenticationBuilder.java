/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.support;

import static org.springframework.security.test.oauth2.support.CollectionsSupport.asSet;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public abstract class AbstractAuthenticationBuilder<T extends AbstractAuthenticationBuilder<T>> {

	public static final String DEFAULT_AUTH_NAME = "user";

	public static final String[] DEFAULT_AUTHORITIES = { "ROLE_USER" };

	public static final String DEFAULT_SCOPE_ATTRIBUTE_NAME = "scope";

	private static final String ROLE_PREFIX = "ROLE_";

	private static final String SCOPE_PREFIX = "SCOPE_";

	protected String name;

	protected final Set<String> authorities;

	private boolean isAuthoritiesSet = false;

	protected final Map<String, Object> claims = new HashMap<>();

	protected String scopeClaimName = DEFAULT_SCOPE_ATTRIBUTE_NAME;

	public AbstractAuthenticationBuilder(final String defaultName, final String[] defaultAuthorities) {
		this.name = defaultName;
		this.authorities = new HashSet<>(asSet(defaultAuthorities));
	}

	public AbstractAuthenticationBuilder() {
		this(DEFAULT_AUTH_NAME, DEFAULT_AUTHORITIES);
	}

	public T name(final String name) {
		this.name = name;
		return downCast();
	}

	public T authority(final String authority) {
		assert (authority != null);
		if (!this.isAuthoritiesSet) {
			this.authorities.clear();
			this.isAuthoritiesSet = true;
		}
		this.authorities.add(authority);
		return downCast();
	}

	public T authorities(final Stream<String> authorities) {
		this.authorities.clear();
		authorities.forEach(this::authority);
		return downCast();
	}

	public T authorities(final String... authorities) {
		return authorities(Stream.of(authorities));
	}

	public T authorities(final Collection<String> authorities) {
		return authorities(authorities.stream());
	}

	public T role(final String role) {
		assert (role != null);
		assert (!role.startsWith(ROLE_PREFIX));
		return authority(ROLE_PREFIX + role);
	}

	public T roles(final Stream<String> roles) {
		this.authorities.removeIf(a -> a.startsWith(ROLE_PREFIX));
		roles.forEach(this::role);
		return downCast();
	}

	public T roles(final String... roles) {
		return roles(Stream.of(roles));
	}

	public T roles(final Collection<String> roles) {
		return roles(roles.stream());
	}

	public T scope(final String scope) {
		assert (scope != null);
		assert (!scope.startsWith(SCOPE_PREFIX));
		return authority(SCOPE_PREFIX + scope);
	}

	public T scopes(final Stream<String> scopes) {
		this.authorities.removeIf(a -> a.startsWith(SCOPE_PREFIX));
		scopes.forEach(this::scope);
		return downCast();
	}

	public T scopes(final String... scopes) {
		return scopes(Stream.of(scopes));
	}

	public T scopes(final Collection<String> scopes) {
		return scopes(scopes.stream());
	}

	public T claim(final String name, final Object value) {
		assert (name != null);
		this.claims.put(name, value);
		return downCast();
	}

	public T claims(final Map<String, Object> attributes) {
		assert (attributes != null);
		this.claims.clear();
		attributes.entrySet().stream().forEach(e -> this.claim(e.getKey(), e.getValue()));
		return downCast();
	}

	public T scopesClaimName(final String name) {
		this.scopeClaimName = name;
		return downCast();
	}

	public Set<SimpleGrantedAuthority> getAllAuthorities() {
		return Stream.concat(authorities.stream(), getScopeAttributeStream().map(scope -> "SCOPE_" + scope))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

	public Set<String> getAllScopes() {
		return Stream
				.concat(
						getScopeAttributeStream(),
						authorities.stream().filter(a -> a.startsWith("SCOPE_")).map(a -> a.substring(6)))
				.collect(Collectors.toSet());
	}

	@SuppressWarnings("unchecked")
	protected T downCast() {
		return (T) this;
	}

	private Stream<String> getScopeAttributeStream() {
		final Object scopeAttribute = claims.get(scopeClaimName);
		if (scopeAttribute == null) {
			return Stream.empty();
		}

		if (scopeAttribute instanceof Collection<?>) {
			return ((Collection<?>) scopeAttribute).stream().map(Object::toString);
		} else if (scopeAttribute instanceof String) {
			return Stream.of(scopeAttribute.toString().split(" "));
		} else {
			throw new RuntimeException(
					"Only Collection<String> or String are supported types for scopes. Was "
							+ scopeAttribute.getClass().getName());
		}
	}

}
