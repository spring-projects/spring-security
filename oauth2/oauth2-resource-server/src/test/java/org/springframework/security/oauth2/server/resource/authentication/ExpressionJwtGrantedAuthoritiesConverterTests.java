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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import org.springframework.expression.spel.standard.SpelExpression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ExpressionJwtGrantedAuthoritiesConverter}
 *
 * @author Thomas Darimont
 * @since 6.4
 */
public class ExpressionJwtGrantedAuthoritiesConverterTests {

	@Test
	public void convertWhenTokenHasCustomClaimNameExpressionThenCustomClaimNameAttributeIsTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("nested", Collections.singletonMap("roles", Arrays.asList("role1", "role2")))
				.build();
		// @formatter:on
		SpelExpression expression = new SpelExpressionParser().parseRaw("[nested][roles]");
		ExpressionJwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new ExpressionJwtGrantedAuthoritiesConverter(
				expression);
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("SCOPE_role1"),
				new SimpleGrantedAuthority("SCOPE_role2"));
	}

	@Test
	public void convertToEmptyListWhenTokenClaimExpressionYieldsNull() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("nested", Collections.singletonMap("roles", null))
				.build();
		// @formatter:on
		SpelExpression expression = new SpelExpressionParser().parseRaw("[nested][roles]");
		ExpressionJwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new ExpressionJwtGrantedAuthoritiesConverter(
				expression);
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

	@Test
	public void convertWhenTokenHasCustomClaimNameExpressionThenCustomClaimNameAttributeIsTranslatedToAuthoritiesWithPrefix() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("nested", Collections.singletonMap("roles", Arrays.asList("role1", "role2")))
				.build();
		// @formatter:on
		SpelExpression expression = new SpelExpressionParser().parseRaw("[nested][roles]");
		ExpressionJwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new ExpressionJwtGrantedAuthoritiesConverter(
				expression);
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("CUSTOM_");
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).containsExactly(new SimpleGrantedAuthority("CUSTOM_role1"),
				new SimpleGrantedAuthority("CUSTOM_role2"));
	}

	@Test
	public void convertWhenTokenHasCustomInvalidClaimNameExpressionThenCustomClaimNameAttributeIsTranslatedToEmptyAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("other", Collections.singletonMap("roles", Arrays.asList("role1", "role2")))
				.build();
		// @formatter:on
		SpelExpression expression = new SpelExpressionParser().parseRaw("[nested][roles]");
		ExpressionJwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new ExpressionJwtGrantedAuthoritiesConverter(
				expression);
		Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
		assertThat(authorities).isEmpty();
	}

}
