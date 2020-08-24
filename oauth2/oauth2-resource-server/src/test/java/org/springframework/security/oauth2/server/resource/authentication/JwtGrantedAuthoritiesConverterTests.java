/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link JwtGrantedAuthoritiesConverter}
 *
 * @author Eric Deandrea
 * @since 5.2
 */
public class JwtGrantedAuthoritiesConverterTests {

	@Test(expected = IllegalArgumentException.class)
	public void setAuthorityPrefixWithNullThenException() {
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix(null);
	}

	@Test
	public void convertWhenTokenHasScopeAttributeThenTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scope", "message:read message:write")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void convertWithCustomAuthorityPrefixWhenTokenHasScopeAttributeThenTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scope", "message:read message:write")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("ROLE_message:read"),
				new SimpleGrantedAuthority("ROLE_message:write"));
	}

	@Test
	public void convertWithBlankAsCustomAuthorityPrefixWhenTokenHasScopeAttributeThenTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scope", "message:read message:write")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("message:read"),
				new SimpleGrantedAuthority("message:write"));
	}

	@Test
	public void convertWhenTokenHasEmptyScopeAttributeThenTranslatedToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scope", "")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

	@Test
	public void convertWhenTokenHasScpAttributeThenTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", Arrays.asList("message:read", "message:write"))
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void convertWithCustomAuthorityPrefixWhenTokenHasScpAttributeThenTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", Arrays.asList("message:read", "message:write"))
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("ROLE_message:read"),
				new SimpleGrantedAuthority("ROLE_message:write"));
	}

	@Test
	public void convertWithBlankAsCustomAuthorityPrefixWhenTokenHasScpAttributeThenTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", "message:read message:write")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("message:read"),
				new SimpleGrantedAuthority("message:write"));
	}

	@Test
	public void convertWhenTokenHasEmptyScpAttributeThenTranslatedToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", Collections.emptyList())
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

	@Test
	public void convertWhenTokenHasBothScopeAndScpThenScopeAttributeIsTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", Arrays.asList("message:read", "message:write"))
				.claim("scope", "missive:read missive:write")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("SCOPE_missive:read"),
				new SimpleGrantedAuthority("SCOPE_missive:write"));
	}

	@Test
	public void convertWhenTokenHasEmptyScopeAndNonEmptyScpThenScopeAttributeIsTranslatedToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", Arrays.asList("message:read", "message:write"))
				.claim("scope", "")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

	@Test
	public void convertWhenTokenHasEmptyScopeAndEmptyScpAttributeThenTranslatesToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", Collections.emptyList())
				.claim("scope", Collections.emptyList())
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

	@Test
	public void convertWhenTokenHasNoScopeAndNoScpAttributeThenTranslatesToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("roles", Arrays.asList("message:read", "message:write"))
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

	@Test
	public void convertWhenTokenHasUnsupportedTypeForScopeThenTranslatesToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scope", new String[] { "message:read", "message:write" })
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

	@Test
	public void convertWhenTokenHasCustomClaimNameThenCustomClaimNameAttributeIsTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("roles", Arrays.asList("message:read", "message:write"))
				.claim("scope", "missive:read missive:write")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void convertWhenTokenHasEmptyCustomClaimNameThenCustomClaimNameAttributeIsTranslatedToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("roles", Collections.emptyList())
				.claim("scope", "missive:read missive:write")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

	@Test
	public void convertWhenTokenHasNoCustomClaimNameThenCustomClaimNameAttributeIsTranslatedToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scope", "missive:read missive:write")
				.build();
		// @formatter:on
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

}
