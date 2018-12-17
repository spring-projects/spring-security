/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @author Joe Grandja
 * @since 5.1
 */
public class OidcIdTokenValidatorTests {
	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration();
	private Map<String, Object> headers = new HashMap<>();
	private Map<String, Object> claims = new HashMap<>();
	private Instant issuedAt = Instant.now();
	private Instant expiresAt = this.issuedAt.plusSeconds(3600);

	@Before
	public void setup() {
		this.headers.put("alg", JwsAlgorithms.RS256);
		this.claims.put(IdTokenClaimNames.ISS, "https://issuer.example.com");
		this.claims.put(IdTokenClaimNames.SUB, "rob");
		this.claims.put(IdTokenClaimNames.AUD, Collections.singletonList("client-id"));
	}

	@Test
	public void validateIdTokenWhenValidThenNoErrors() {
		assertThat(this.validateIdToken()).isEmpty();
	}

	@Test
	public void validateIdTokenWhenIssuerNullThenHasErrors() {
		this.claims.remove(IdTokenClaimNames.ISS);
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenSubNullThenHasErrors() {
		this.claims.remove(IdTokenClaimNames.SUB);
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenAudNullThenHasErrors() {
		this.claims.remove(IdTokenClaimNames.AUD);
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenIssuedAtNullThenHasErrors() {
		this.issuedAt = null;
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenExpiresAtNullThenHasErrors() {
		this.expiresAt = null;
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenAudMultipleAndAzpNullThenHasErrors() {
		this.claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id", "other"));
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenAzpNotClientIdThenHasErrors() {
		this.claims.put(IdTokenClaimNames.AZP, "other");
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenMultipleAudAzpClientIdThenNoErrors() {
		this.claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id", "other"));
		this.claims.put(IdTokenClaimNames.AZP, "client-id");
		assertThat(this.validateIdToken()).isEmpty();
	}

	@Test
	public void validateIdTokenWhenMultipleAudAzpNotClientIdThenHasErrors() {
		this.claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id-1", "client-id-2"));
		this.claims.put(IdTokenClaimNames.AZP, "other-client");
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenAudNotClientIdThenHasErrors() {
		this.claims.put(IdTokenClaimNames.AUD, Collections.singletonList("other-client"));
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenExpiredThenHasErrors() {
		this.issuedAt = Instant.now().minus(Duration.ofMinutes(1));
		this.expiresAt = this.issuedAt.plus(Duration.ofSeconds(1));
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenIssuedAtWayInFutureThenHasErrors() {
		this.issuedAt = Instant.now().plus(Duration.ofMinutes(5));
		this.expiresAt = this.issuedAt.plus(Duration.ofSeconds(1));
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	@Test
	public void validateIdTokenWhenExpiresAtBeforeNowThenHasErrors() {
		this.issuedAt = Instant.now().minusSeconds(10);
		this.expiresAt = Instant.from(this.issuedAt).plusSeconds(5);
		assertThat(this.validateIdToken())
				.hasSize(1)
				.extracting(OAuth2Error::getErrorCode)
				.contains("invalid_id_token");
	}

	private Collection<OAuth2Error> validateIdToken() {
		Jwt idToken = new Jwt("token123", this.issuedAt, this.expiresAt, this.headers, this.claims);
		OidcIdTokenValidator validator = new OidcIdTokenValidator(this.registration.build());
		return validator.validate(idToken).getErrors();
	}
}
