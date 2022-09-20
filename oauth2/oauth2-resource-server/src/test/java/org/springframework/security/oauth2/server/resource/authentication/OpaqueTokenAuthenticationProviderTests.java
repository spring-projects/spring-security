/*
 * Copyright 2002-2022 the original author or authors.
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
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.TestOAuth2AuthenticatedPrincipals;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OpaqueTokenAuthenticationProvider}
 *
 * @author Josh Cummings
 */
public class OpaqueTokenAuthenticationProviderTests {

	@Test
	public void authenticateWhenActiveTokenThenOk() throws Exception {
		OAuth2AuthenticatedPrincipal principal = TestOAuth2AuthenticatedPrincipals
				.active((attributes) -> attributes.put("extension_field", "twenty-seven"));
		OpaqueTokenIntrospector introspector = mock(OpaqueTokenIntrospector.class);
		given(introspector.introspect(any())).willReturn(principal);
		OpaqueTokenAuthenticationProvider provider = new OpaqueTokenAuthenticationProvider(introspector);
		Authentication result = provider.authenticate(new BearerTokenAuthenticationToken("token"));
		assertThat(result.getPrincipal()).isInstanceOf(OAuth2IntrospectionAuthenticatedPrincipal.class);
		Map<String, Object> attributes = ((OAuth2AuthenticatedPrincipal) result.getPrincipal()).getAttributes();
		// @formatter:off
		assertThat(attributes)
				.isNotNull()
				.containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
				.containsEntry(OAuth2TokenIntrospectionClaimNames.AUD,
						Arrays.asList("https://protected.example.net/resource"))
				.containsEntry(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, "l238j323ds-23ij4")
				.containsEntry(OAuth2TokenIntrospectionClaimNames.EXP, Instant.ofEpochSecond(1419356238))
				.containsEntry(OAuth2TokenIntrospectionClaimNames.ISS, new URL("https://server.example.com/"))
				.containsEntry(OAuth2TokenIntrospectionClaimNames.NBF, Instant.ofEpochSecond(29348723984L))
				.containsEntry(OAuth2TokenIntrospectionClaimNames.SCOPE, Arrays.asList("read", "write", "dolphin"))
				.containsEntry(OAuth2TokenIntrospectionClaimNames.SUB, "Z5O3upPC88QrAjx00dis")
				.containsEntry(OAuth2TokenIntrospectionClaimNames.USERNAME, "jdoe")
				.containsEntry("extension_field", "twenty-seven");
		assertThat(result.getAuthorities())
				.extracting("authority")
				.containsExactly("SCOPE_read", "SCOPE_write",
				"SCOPE_dolphin");
		// @formatter:on
	}

	@Test
	public void authenticateWhenMissingScopeAttributeThenNoAuthorities() {
		OAuth2AuthenticatedPrincipal principal = new OAuth2IntrospectionAuthenticatedPrincipal(
				Collections.singletonMap("claim", "value"), null);
		OpaqueTokenIntrospector introspector = mock(OpaqueTokenIntrospector.class);
		given(introspector.introspect(any())).willReturn(principal);
		OpaqueTokenAuthenticationProvider provider = new OpaqueTokenAuthenticationProvider(introspector);
		Authentication result = provider.authenticate(new BearerTokenAuthenticationToken("token"));
		assertThat(result.getPrincipal()).isInstanceOf(OAuth2AuthenticatedPrincipal.class);
		Map<String, Object> attributes = ((OAuth2AuthenticatedPrincipal) result.getPrincipal()).getAttributes();
		// @formatter:off
		assertThat(attributes)
				.isNotNull()
				.doesNotContainKey(OAuth2TokenIntrospectionClaimNames.SCOPE);
		// @formatter:on
		assertThat(result.getAuthorities()).isEmpty();
	}

	@Test
	public void authenticateWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() {
		OpaqueTokenIntrospector introspector = mock(OpaqueTokenIntrospector.class);
		given(introspector.introspect(any())).willThrow(new OAuth2IntrospectionException("with \"invalid\" chars"));
		OpaqueTokenAuthenticationProvider provider = new OpaqueTokenAuthenticationProvider(introspector);
		assertThatExceptionOfType(AuthenticationServiceException.class)
				.isThrownBy(() -> provider.authenticate(new BearerTokenAuthenticationToken("token")));
	}

	@Test
	public void constructorWhenIntrospectionClientIsNullThenIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OpaqueTokenAuthenticationProvider(null));
		// @formatter:on
	}

	@Test
	public void setAuthenticationConverterWhenNullThenThrowsIllegalArgumentException() {
		OpaqueTokenIntrospector introspector = mock(OpaqueTokenIntrospector.class);
		OpaqueTokenAuthenticationProvider provider = new OpaqueTokenAuthenticationProvider(introspector);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> provider.setAuthenticationConverter(null))
				.withMessage("authenticationConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void authenticateWhenCustomAuthenticationConverterThenUses() {
		OpaqueTokenIntrospector introspector = mock(OpaqueTokenIntrospector.class);
		OAuth2AuthenticatedPrincipal principal = TestOAuth2AuthenticatedPrincipals.active();
		given(introspector.introspect(any())).willReturn(principal);
		OpaqueTokenAuthenticationProvider provider = new OpaqueTokenAuthenticationProvider(introspector);
		OpaqueTokenAuthenticationConverter authenticationConverter = mock(OpaqueTokenAuthenticationConverter.class);
		given(authenticationConverter.convert(any(), any(OAuth2AuthenticatedPrincipal.class)))
				.willReturn(new TestingAuthenticationToken(principal, null, Collections.emptyList()));
		provider.setAuthenticationConverter(authenticationConverter);

		Authentication result = provider.authenticate(new BearerTokenAuthenticationToken("token"));
		assertThat(result).isNotNull();
		verify(introspector).introspect("token");
		verify(authenticationConverter).convert("token", principal);
		verifyNoMoreInteractions(introspector, authenticationConverter);
	}

}
