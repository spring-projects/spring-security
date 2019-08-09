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

import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

import org.junit.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2TokenAttributes;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ACTIVE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SCOPE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SUBJECT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.USERNAME;
import static org.springframework.security.oauth2.server.resource.introspection.TestOAuth2TokenIntrospectionClientResponses.active;

/**
 * Tests for {@link OAuth2IntrospectionAuthenticationProvider}
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class OAuth2IntrospectionAuthenticationProviderTests {
	@Test
	public void authenticateWhenActiveTokenThenOk() throws Exception {
		Map<String, Object> claims = active();
		claims.put("extension_field", "twenty-seven");
		OpaqueTokenIntrospector introspectionClient = mock(OpaqueTokenIntrospector.class);
		when(introspectionClient.introspect(any())).thenReturn(claims);
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(introspectionClient);

		Authentication result =
				provider.authenticate(new BearerTokenAuthenticationToken("token"));

		assertThat(result.getPrincipal()).isInstanceOf(OAuth2TokenAttributes.class);

		Map<String, Object> attributes = ((OAuth2TokenAttributes) result.getPrincipal()).getAttributes();
		assertThat(attributes)
				.isNotNull()
				.containsEntry(ACTIVE, true)
				.containsEntry(AUDIENCE, Arrays.asList("https://protected.example.net/resource"))
				.containsEntry(OAuth2IntrospectionClaimNames.CLIENT_ID, "l238j323ds-23ij4")
				.containsEntry(EXPIRES_AT, Instant.ofEpochSecond(1419356238))
				.containsEntry(ISSUER, new URL("https://server.example.com/"))
				.containsEntry(NOT_BEFORE, Instant.ofEpochSecond(29348723984L))
				.containsEntry(SCOPE, Arrays.asList("read", "write", "dolphin"))
				.containsEntry(SUBJECT, "Z5O3upPC88QrAjx00dis")
				.containsEntry(USERNAME, "jdoe")
				.containsEntry("extension_field", "twenty-seven");

		assertThat(result.getAuthorities()).extracting("authority")
				.containsExactly("SCOPE_read", "SCOPE_write", "SCOPE_dolphin");
	}

	@Test
	public void authenticateWhenMissingScopeAttributeThenNoAuthorities() {
		Map<String, Object> claims = active();
		claims.remove(SCOPE);
		OpaqueTokenIntrospector introspectionClient = mock(OpaqueTokenIntrospector.class);
		when(introspectionClient.introspect(any())).thenReturn(claims);
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(introspectionClient);

		Authentication result =
				provider.authenticate(new BearerTokenAuthenticationToken("token"));
		assertThat(result.getPrincipal()).isInstanceOf(OAuth2TokenAttributes.class);

		Map<String, Object> attributes = ((OAuth2TokenAttributes) result.getPrincipal()).getAttributes();
		assertThat(attributes)
				.isNotNull()
				.doesNotContainKey(SCOPE);

		assertThat(result.getAuthorities()).isEmpty();
	}

	@Test
	public void authenticateWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() {
		OpaqueTokenIntrospector introspectionClient = mock(OpaqueTokenIntrospector.class);
		when(introspectionClient.introspect(any())).thenThrow(new OAuth2IntrospectionException("with \"invalid\" chars"));
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(introspectionClient);

		assertThatCode(() -> provider.authenticate(new BearerTokenAuthenticationToken("token")))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting("error.description")
				.containsExactly("An error occurred while attempting to introspect the token: Invalid token");
	}

	@Test
	public void constructorWhenIntrospectionClientIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new OAuth2IntrospectionAuthenticationProvider(null))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
