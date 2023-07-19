/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication.logout;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OidcBackChannelLogoutTokenValidator}
 */
public class OidcBackChannelLogoutTokenValidatorTests {

	// @formatter:off
	private final ClientRegistration clientRegistration = TestClientRegistrations
			.clientRegistration()
			.issuerUri("https://issuer")
			.scope("openid").build();
	// @formatter:on

	private final OidcBackChannelLogoutTokenValidator logoutTokenValidator = new OidcBackChannelLogoutTokenValidator(
			this.clientRegistration);

	@Test
	public void createDecoderWhenTokenValidThenNoErrors() {
		Jwt valid = valid(this.clientRegistration).build();
		assertThat(this.logoutTokenValidator.validate(valid).hasErrors()).isFalse();
	}

	@Test
	public void createDecoderWhenInvalidAudienceThenErrors() {
		Jwt valid = valid(this.clientRegistration).audience(List.of("wrong")).build();
		assertThat(this.logoutTokenValidator.validate(valid).hasErrors()).isTrue();
	}

	@Test
	public void createDecoderWhenMissingEventsThenErrors() {
		Jwt valid = valid(this.clientRegistration).claims((claims) -> claims.remove(LogoutTokenClaimNames.EVENTS))
				.build();
		assertThat(this.logoutTokenValidator.validate(valid).hasErrors()).isTrue();
	}

	@Test
	public void createDecoderWhenInvalidIssuerThenErrors() {
		Jwt valid = valid(this.clientRegistration).issuer("https://wrong").build();
		assertThat(this.logoutTokenValidator.validate(valid).hasErrors()).isTrue();
	}

	@Test
	public void createDecoderWhenMissingSubjectThenErrors() {
		Jwt valid = valid(this.clientRegistration).claims((claims) -> claims.remove(LogoutTokenClaimNames.SUB)).build();
		assertThat(this.logoutTokenValidator.validate(valid).hasErrors()).isTrue();
	}

	@Test
	public void createDecoderWhenMissingAudienceThenErrors() {
		Jwt valid = valid(this.clientRegistration).claims((claims) -> claims.remove(LogoutTokenClaimNames.AUD)).build();
		assertThat(this.logoutTokenValidator.validate(valid).hasErrors()).isTrue();
	}

	private Jwt.Builder valid(ClientRegistration clientRegistration) {
		String issuerUri = clientRegistration.getProviderDetails().getIssuerUri();
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSubject(issuerUri, "subject").build();
		return Jwt.withTokenValue(logoutToken.getTokenValue()).header("header", "value")
				.claims((claims) -> claims.putAll(logoutToken.getClaims()));
	}

}
