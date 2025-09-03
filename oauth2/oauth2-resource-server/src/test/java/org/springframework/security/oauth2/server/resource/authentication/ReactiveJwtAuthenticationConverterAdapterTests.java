/*
 * Copyright 2004-present the original author or authors.
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
import java.util.function.Predicate;

import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.SecurityAssertions;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;

/**
 * Tests for {@link ReactiveJwtAuthenticationConverterAdapter}
 *
 * @author Josh Cummings
 */
public class ReactiveJwtAuthenticationConverterAdapterTests {

	Converter<Jwt, AbstractAuthenticationToken> converter = new JwtAuthenticationConverter();

	ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverterAdapter(
			this.converter);

	@Test
	public void convertWhenTokenHasScopeAttributeThenTranslatedToAuthorities() {
		Jwt jwt = TestJwts.jwt().claim("scope", "message:read message:write").build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt).block();
		SecurityAssertions.assertThat(authentication).hasAuthorities("SCOPE_message:read", "SCOPE_message:write");
	}

	@Test
	public void convertWhenTokenHasEmptyScopeAttributeThenTranslatedToNoAuthorities() {
		Jwt jwt = TestJwts.jwt().claim("scope", "").build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt).block();
		SecurityAssertions.assertThat(authentication).authorities().noneMatch(isScope());
	}

	@Test
	public void convertWhenTokenHasScpAttributeThenTranslatedToAuthorities() {
		Jwt jwt = TestJwts.jwt().claim("scp", Arrays.asList("message:read", "message:write")).build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt).block();
		SecurityAssertions.assertThat(authentication).hasAuthorities("SCOPE_message:read", "SCOPE_message:write");
	}

	@Test
	public void convertWhenTokenHasEmptyScpAttributeThenTranslatedToNoAuthorities() {
		Jwt jwt = TestJwts.jwt().claim("scp", Arrays.asList()).build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt).block();
		SecurityAssertions.assertThat(authentication).authorities().noneMatch(isScope());
	}

	@Test
	public void convertWhenTokenHasBothScopeAndScpThenScopeAttributeIsTranslatedToAuthorities() {
		Jwt jwt = TestJwts.jwt()
			.claim("scp", Arrays.asList("message:read", "message:write"))
			.claim("scope", "missive:read missive:write")
			.build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt).block();
		SecurityAssertions.assertThat(authentication).hasAuthorities("SCOPE_missive:read", "SCOPE_missive:write");
	}

	@Test
	public void convertWhenTokenHasEmptyScopeAndNonEmptyScpThenScopeAttributeIsTranslatedToNoAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("scp", Arrays.asList("message:read", "message:write"))
				.claim("scope", "")
				.build();
		// @formatter:on
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt).block();
		SecurityAssertions.assertThat(authentication).authorities().noneMatch(isScope());
	}

	static Predicate<GrantedAuthority> isScope() {
		return (a) -> a.getAuthority().startsWith("SCOPE_");
	}

}
