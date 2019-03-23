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
package org.springframework.security.test.context.support.oauth2.request;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.springframework.security.test.context.support.oauth2.support.CollectionsSupport.asSet;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public abstract class AbstractOAuth2RequestPostProcessor<T extends AbstractOAuth2RequestPostProcessor<T>>
		implements
		RequestPostProcessor {

	private static final String ROLE_PREFIX = "ROLE_";

	private static final String SCOPE_PREFIX = "SCOPE_";

	protected String name;

	protected final Collection<String> authorities;

	protected boolean isAuthoritiesSet = false;

	protected final Collection<String> scopes = new HashSet<>();

	protected final Map<String, Object> attributes = new HashMap<>();

	protected AbstractOAuth2RequestPostProcessor(final String defaultName, final String[] defaultAuthorities) {
		this.name = defaultName;
		this.authorities = new HashSet<>(asSet(defaultAuthorities));
	}

	public T name(final String name) {
		this.name = name;
		return downCast();
	}

	public T authority(final String authority) {
		assertNotNull(authority);
		this.isAuthoritiesSet = true;
		this.authorities.add(authority);
		if (authority.startsWith(SCOPE_PREFIX)) {
			this.scopes.add(authority.substring(SCOPE_PREFIX.length()));
		}
		return downCast();
	}

	public T authorities(final String... authorities) {
		Stream.of(authorities).forEach(this::authority);
		return downCast();
	}

	public T role(final String role) {
		assertNotNull(role);
		assertFalse(role.startsWith(ROLE_PREFIX));
		return authority(ROLE_PREFIX + role);
	}

	public T roles(final String... roles) {
		Stream.of(roles).forEach(this::role);
		return downCast();
	}

	public T scope(final String role) {
		assertNotNull(role);
		assertFalse(role.startsWith(SCOPE_PREFIX));
		return authority(SCOPE_PREFIX + role);
	}

	public T scopes(final String... scope) {
		Stream.of(scope).forEach(this::role);
		return downCast();
	}

	public T attributes(final Map<String, Object> attributes) {
		assertNotNull(attributes);
		attributes.entrySet().stream().forEach(e -> this.attribute(e.getKey(), e.getValue()));
		return downCast();
	}

	public T attribute(final String name, final Object value) {
		assertNotNull(name);
		this.attributes.put(name, value);
		return downCast();
	}

	@SuppressWarnings("unchecked")
	private T downCast() {
		return (T) this;
	}

}
