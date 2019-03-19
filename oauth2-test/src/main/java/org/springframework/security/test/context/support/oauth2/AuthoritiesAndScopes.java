/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2;

import static org.springframework.security.test.context.support.oauth2.AnnotationHelper.putIfNotEmpty;

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
	 * <p>
	 * Merges {@code authorities} and {@code scope}.
	 * </p>
	 * <p>
	 * Scopes are searched for in attributes with keys "scope", "scp" and "scopes", first entry found being used and
	 * others ignored.
	 * </p>
	 *
	 * <pre>
	 * &#64;Foo(
	 * 		authorities = { "ROLE_R", "SCOPE_s1" },
	 * 		scopes = { "s2" },
	 * 		attributes = &#64;Attribute(name = "scope", value = "s3", parseTo = TargetType.STRING_SET))
	 * static final class Decorated {
	 * }
	 *
	 * &#64;Test
	 * public void testScopesAndAuthorities() {
	 * 	final Foo annotation = AnnotationUtils.findAnnotation(Decorated.class, Foo.class);
	 * 	final Map<String, Object> attributes =
	 * 			new HashMap<>(AttributeParsersHelper.withDefaultParsers().parse(annotation.attributes()));
	 *
	 * 	Set<String> scopeAttributeBeforeGet = (Set<String>) attributes.get("scope");
	 * 	assertThat(scopeAttributeAfterGet).hasSize(1);
	 * 	assertThat(scopeAttributeAfterGet).contains("s3");
	 *
	 * 	AuthoritiesAndScopes actual =
	 * 			AuthoritiesAndScopes.get(annotation.authorities(), annotation.scopes(), attributes);
	 *
	 * 	assertThat(actual.scopes).hasSize(3);
	 * 	assertThat(actual.scopes).contains("s1"); // from "SCOPE_s1" authority
	 * 	assertThat(actual.scopes).contains("s2"); // from "Foo::scopes"
	 * 	assertThat(actual.scopes).contains("s3"); // from scope attribute
	 *
	 * 	assertThat(actual.authorities).hasSize(4);
	 * 	assertThat(actual.authorities).contains("ROLE_R"); // from authorities
	 * 	assertThat(actual.authorities).contains("SCOPE_s1"); // from authorities
	 * 	assertThat(actual.authorities).contains("SCOPE_s2"); // from "Foo::scopes"
	 * 	assertThat(actual.authorities).contains("SCOPE_s3"); // from scope attribute
	 *
	 * 	Set<String> scopeAttributeAfterGet = (Set<String>) attributes.get("scope");
	 * 	assertThat(scopeAttributeAfterGet).hasSize(3);
	 * 	assertThat(scopeAttributeAfterGet).contains("s1");
	 * 	assertThat(scopeAttributeAfterGet).contains("s2");
	 * 	assertThat(scopeAttributeAfterGet).contains("s3");
	 * }
	 * </pre>
	 *
	 * @param annotatedAuthorities authorities array (probably from an annotation {@code authorities()})
	 * @param annotatedScopes scopes array (probably from an annotation {@code scopes()})
	 * @param attributes attributes <b>/!\ mutable /!\</b> map (probably from an annotation {@code attributes()} or
	 * {@code claims()})
	 * @return a structure containing merged granted authorities and scopes
	 */
	public static AuthoritiesAndScopes get(
			final String[] annotatedAuthorities,
			final String[] annotatedScopes,
			final Map<String, Object> attributes) {
		final Optional<String> scopeAttributeName = attributes.keySet()
				.stream()
				.filter(k -> "scope".equals(k) || "scp".equals(k) || "scopes".equals(k))
				.sorted()
				.findFirst();

		final Stream<String> attributesScopes =
				scopeAttributeName.map(attributes::get).map(AuthoritiesAndScopes::stream).orElse(Stream.empty());

		final Stream<String> authoritiesScopes =
				Stream.of(annotatedAuthorities).filter(a -> a.startsWith("SCOPE_")).map(a -> a.substring(6));

		final Set<String> allScopes =
				Stream.concat(Stream.of(annotatedScopes), Stream.concat(authoritiesScopes, attributesScopes))
						.collect(Collectors.toSet());

		putIfNotEmpty(scopeAttributeName.orElse("scope"), allScopes, attributes);

		final Set<SimpleGrantedAuthority> allAuthorities =
				Stream.concat(Stream.of(annotatedAuthorities), allScopes.stream().map(scope -> "SCOPE_" + scope))
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toSet());

		return new AuthoritiesAndScopes(allAuthorities, allScopes, scopeAttributeName);
	}

	@SuppressWarnings("unchecked")
	private static Stream<String> stream(final Object col) {
		return col == null ? Stream.empty() : ((Collection<String>) col).stream();
	}
}