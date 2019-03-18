package org.springframework.security.test.context.support.oauth2;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class AuthoritiesAndScopesTest {

	@Test
	public void testScopeAttribute() {
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("scope", Collections.singleton("c"));
		final AuthoritiesAndScopes actual =
				AuthoritiesAndScopes.get(new String[] { "AUTHORITY_A", "SCOPE_a" }, new String[] { "b" }, attributes);

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
	public void testScpAttribute() {
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("scp", Collections.singleton("c"));
		final AuthoritiesAndScopes actual =
				AuthoritiesAndScopes.get(new String[] { "AUTHORITY_A", "SCOPE_a" }, new String[] { "b" }, attributes);

		assertThat(actual.authorities).hasSize(4);
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("AUTHORITY_A"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_a"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_b"));
		assertThat(actual.authorities).contains(new SimpleGrantedAuthority("SCOPE_c"));

		assertThat(actual.scopes).hasSize(3);
		assertThat(actual.scopes).contains("a");
		assertThat(actual.scopes).contains("b");
		assertThat(actual.scopes).contains("c");

		assertThat(actual.scopeAttributeName).isEqualTo(Optional.of("scp"));
	}

	@Test
	public void testScopesAttribute() {
		final Map<String, Object> attributes = new HashMap<>();
		attributes.put("scopes", Collections.singleton("c"));
		final AuthoritiesAndScopes actual =
				AuthoritiesAndScopes.get(new String[] { "AUTHORITY_A", "SCOPE_a" }, new String[] { "b" }, attributes);

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
				AuthoritiesAndScopes.get(new String[] { "AUTHORITY_A", "SCOPE_a" }, new String[] { "b" }, attributes);

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
