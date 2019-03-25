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
package org.springframework.security.test.context.support.oauth2.support;

import static org.springframework.security.test.context.support.oauth2.support.CollectionsSupport.putIfNotEmpty;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Helps merging {@code authorities} and {@code scope}.
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
final class AuthoritiesAndScopes {
	public final Set<SimpleGrantedAuthority> authorities;
	public final Set<String> scopes;
	public final Optional<String> scopeAttributeName;

	private AuthoritiesAndScopes(
			final Set<SimpleGrantedAuthority> authorities,
			final Set<String> scopes,
			final Optional<String> scopeAttributeName) {
		this.authorities = Collections.unmodifiableSet(authorities);
		this.scopes = Collections.unmodifiableSet(scopes);
		this.scopeAttributeName = scopeAttributeName;
	}

	/**
	 * Merges {@code authorities} and {@code scope}. Scopes are scanned for in:
	 * <ul>
	 * <li>scopes of course</li>
	 * <li>authorities ("SCOPE_" prefix)</li>
	 * <li>claims with keys "scope", "scp" and "scopes", first entry found being used and
	 * others ignored</li>
	 * </ul>
	 * <p>
	 * All scopes are merged and set in claims, authorities and allScopes
	 * </p>
	 *
	 * @param authorities authorities array (probably from an annotation
	 * {@code authorities()})
	 * @param scopes scopes array (probably from an annotation {@code scopes()})
	 * @param attributes attributes <b>/!\ mutable /!\</b> map (probably from an
	 * annotation {@code attributes()} or {@code claims()})
	 * @return a structure containing merged granted authorities and scopes
	 */
	public static AuthoritiesAndScopes get(
			final Collection<String> authorities,
			final Collection<String> scopes,
			final Map<String, Object> attributes) {

		final Optional<String> scopeAttributeName = attributes.keySet()
				.stream()
				.filter(k -> "scope".equals(k) || "scp".equals(k) || "scopes".equals(k))
				.sorted()
				.findFirst();

		final Optional<Object> scopeAttribute = scopeAttributeName.map(attributes::get);

		final boolean scopeIsString = scopeAttribute.map(s -> s instanceof String).orElse(false);

		final Stream<String> attributesScopes = scopeAttribute.map(s -> {
			if (scopeIsString) {
				return Stream.of(scopeAttribute.get().toString().split(" "));
			}
			return AuthoritiesAndScopes.asStringStream(scopeAttribute.get());
		}).orElse(Stream.empty());

		final Stream<String> authoritiesScopes =
				authorities.stream().filter(a -> a.startsWith("SCOPE_")).map(a -> a.substring(6));

		final Set<String> allScopes = Stream.concat(scopes.stream(), Stream.concat(authoritiesScopes, attributesScopes))
				.collect(Collectors.toSet());

		if (scopeIsString) {
			putIfNotEmpty(
					scopeAttributeName.orElse("scope"),
					allScopes.stream().collect(Collectors.joining(" ")),
					attributes);
		} else {
			putIfNotEmpty(scopeAttributeName.orElse("scope"), allScopes, attributes);
		}

		final Set<SimpleGrantedAuthority> allAuthorities =
				Stream.concat(authorities.stream(), allScopes.stream().map(scope -> "SCOPE_" + scope))
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toSet());

		return new AuthoritiesAndScopes(allAuthorities, allScopes, scopeAttributeName);
	}

	@SuppressWarnings("unchecked")
	private static Stream<String> asStringStream(final Object col) {
		return col == null ? Stream.empty() : ((Collection<String>) col).stream();
	}
}