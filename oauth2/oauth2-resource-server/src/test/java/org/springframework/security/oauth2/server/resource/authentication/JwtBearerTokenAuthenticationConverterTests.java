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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Arrays;

import org.junit.Test;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link JwtBearerTokenAuthenticationConverter}
 *
 * @author Josh Cummings
 */
public class JwtBearerTokenAuthenticationConverterTests {

	private final JwtBearerTokenAuthenticationConverter converter = new JwtBearerTokenAuthenticationConverter();

	@Test
	public void convertWhenJwtThenBearerTokenAuthentication() {
		Jwt jwt = Jwt.withTokenValue("token-value").claim("claim", "value").header("header", "value").build();

		AbstractAuthenticationToken token = this.converter.convert(jwt);

		assertThat(token).isInstanceOf(BearerTokenAuthentication.class);
		BearerTokenAuthentication bearerToken = (BearerTokenAuthentication) token;
		assertThat(bearerToken.getToken().getTokenValue()).isEqualTo("token-value");
		assertThat(bearerToken.getTokenAttributes()).containsOnlyKeys("claim");
		assertThat(bearerToken.getAuthorities()).isEmpty();
	}

	@Test
	public void convertWhenJwtWithScopeAttributeThenBearerTokenAuthentication() {
		Jwt jwt = Jwt.withTokenValue("token-value").claim("scope", "message:read message:write")
				.header("header", "value").build();

		AbstractAuthenticationToken token = this.converter.convert(jwt);

		assertThat(token).isInstanceOf(BearerTokenAuthentication.class);
		BearerTokenAuthentication bearerToken = (BearerTokenAuthentication) token;
		assertThat(bearerToken.getAuthorities()).containsExactly(new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void convertWhenJwtWithScpAttributeThenBearerTokenAuthentication() {
		Jwt jwt = Jwt.withTokenValue("token-value").claim("scp", Arrays.asList("message:read", "message:write"))
				.header("header", "value").build();

		AbstractAuthenticationToken token = this.converter.convert(jwt);

		assertThat(token).isInstanceOf(BearerTokenAuthentication.class);
		BearerTokenAuthentication bearerToken = (BearerTokenAuthentication) token;
		assertThat(bearerToken.getAuthorities()).containsExactly(new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

}
