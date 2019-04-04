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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.oauth2.support.CollectionsSupport.asSet;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class AuthoritiesAndScopesTest {

	@Test
	public void testScopeCollectionAttribute() {
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("scope", Collections.singleton("c"));
		final AuthoritiesAndScopes actual =
				AuthoritiesAndScopes.get(asSet("AUTHORITY_A", "SCOPE_a"), asSet("b"), attributes);

		assertThat(actual.authorities).hasSize(4);
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("AUTHORITY_A"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_a"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_b"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_c"));

		assertThat(actual.scopes).hasSize(3);
		assertThat(actual.scopes).contains("a");
		assertThat(actual.scopes).contains("b");
		assertThat(actual.scopes).contains("c");

		assertThat(actual.scopeAttributeName).isEqualTo(Optional.of("scope"));
	}

	@Test
	public void testScopeStringAttribute() {
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("scope", "c");
		final AuthoritiesAndScopes actual =
				AuthoritiesAndScopes.get(asSet("AUTHORITY_A", "SCOPE_a"), asSet("b"), attributes);

		assertThat(actual.authorities).hasSize(4);
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("AUTHORITY_A"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_a"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_b"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_c"));

		assertThat(actual.scopes).hasSize(3);
		assertThat(actual.scopes).contains("a");
		assertThat(actual.scopes).contains("b");
		assertThat(actual.scopes).contains("c");

		assertThat(attributes.get("scope")).isEqualTo("a b c");

		assertThat(actual.scopeAttributeName).isEqualTo(Optional.of("scope"));
	}

	@Test
	public void testScpAttribute() {
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("scp", Collections.singleton("c"));
		final AuthoritiesAndScopes actual =
				AuthoritiesAndScopes.get(asSet("AUTHORITY_A", "SCOPE_a"), asSet("b"), attributes);

		assertThat(actual.authorities).hasSize(4);
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("AUTHORITY_A"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_a"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_b"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_c"));

		assertThat(actual.scopes).hasSize(3);
		assertThat(actual.scopes).contains("a");
		assertThat(actual.scopes).contains("b");
		assertThat(actual.scopes).contains("c");

		assertThat(attributes.get("scp")).isEqualTo(actual.scopes);

		assertThat(actual.scopeAttributeName).isEqualTo(Optional.of("scp"));
	}

	@Test
	public void testScopesAttribute() {
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("scopes", Collections.singleton("c"));
		final AuthoritiesAndScopes actual =
				AuthoritiesAndScopes.get(asSet("AUTHORITY_A", "SCOPE_a"), asSet("b"), attributes);

		assertThat(actual.authorities).hasSize(4);
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("AUTHORITY_A"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_a"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_b"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_c"));

		assertThat(actual.scopes).hasSize(3);
		assertThat(actual.scopes).contains("a");
		assertThat(actual.scopes).contains("b");
		assertThat(actual.scopes).contains("c");

		assertThat(actual.scopeAttributeName).isEqualTo(Optional.of("scopes"));
	}

	@Test
	public void testAttributeCollision() {
		final Map<String, Object> attributes = new HashMap<>(3);
		attributes.put("scopes", Collections.singleton("c"));
		attributes.put("scope", Collections.singleton("d"));
		attributes.put("scp", Collections.singleton("e"));
		final AuthoritiesAndScopes actual =
				AuthoritiesAndScopes.get(asSet("AUTHORITY_A", "SCOPE_a"), asSet("b"), attributes);

		assertThat(actual.authorities).hasSize(4);
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("AUTHORITY_A"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_a"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_b"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_d"));

		assertThat(actual.scopes).hasSize(3);
		assertThat(actual.scopes).contains("a");
		assertThat(actual.scopes).contains("b");
		assertThat(actual.scopes).contains("d");

		assertThat(actual.scopeAttributeName).isEqualTo(Optional.of("scope"));
	}

}
