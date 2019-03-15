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

package org.springframework.security.oauth2.client.oidc.authentication;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class OidcTokenValidatorTests {
	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration();

	private Map<String, Object> claims = new HashMap<>();
	private Instant issuedAt = Instant.now();
	private Instant expiresAt = Instant.now().plusSeconds(3600);

	@Before
	public void setup() {
		this.claims.put(IdTokenClaimNames.ISS, "https://issuer.example.com");
		this.claims.put(IdTokenClaimNames.SUB, "rob");
		this.claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id"));
	}

	@Test
	public void validateIdTokenWhenValidThenNoException() {
		assertThatCode(() -> validateIdToken())
				.doesNotThrowAnyException();
	}

	@Test
	public void validateIdTokenWhenIssuerNullThenException() {
		this.claims.remove(IdTokenClaimNames.ISS);
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void validateIdTokenWhenSubNullThenException() {
		this.claims.remove(IdTokenClaimNames.SUB);
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void validateIdTokenWhenAudNullThenException() {
		this.claims.remove(IdTokenClaimNames.AUD);
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void validateIdTokenWhenIssuedAtNullThenException() {
		this.issuedAt = null;
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void validateIdTokenWhenExpiresAtNullThenException() {
		this.expiresAt = null;
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void validateIdTokenWhenAudMultipleAndAzpNullThenException() {
		this.claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id", "other"));
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void validateIdTokenWhenAzpNotClientIdThenException() {
		this.claims.put(IdTokenClaimNames.AZP, "other");
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void validateIdTokenWhenMulitpleAudAzpClientIdThenNoException() {
		this.claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id", "other"));
		this.claims.put(IdTokenClaimNames.AZP, "client-id");
		assertThatCode(() -> validateIdToken())
				.doesNotThrowAnyException();
	}

	@Test
	public void validateIdTokenWhenExpiredThenException() {
		this.issuedAt = Instant.now().minus(Duration.ofMinutes(1));
		this.expiresAt = this.issuedAt.plus(Duration.ofSeconds(1));
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void validateIdTokenWhenIssuedAtWayInFutureThenException() {
		this.issuedAt = Instant.now().plus(Duration.ofMinutes(5));
		this.expiresAt = this.issuedAt.plus(Duration.ofSeconds(1));
		assertThatCode(() -> validateIdToken())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	private void validateIdToken() {
		OidcIdToken token = new OidcIdToken("token123", this.issuedAt, this.expiresAt, this.claims);
		OidcTokenValidator.validateIdToken(token, this.registration.build());
	}

}
