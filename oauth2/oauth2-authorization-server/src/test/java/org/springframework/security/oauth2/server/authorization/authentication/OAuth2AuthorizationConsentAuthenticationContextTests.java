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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2AuthorizationConsentAuthenticationContext}.
 *
 * @author Steve Riesenberg
 * @author Joe Grandja
 */
public class OAuth2AuthorizationConsentAuthenticationContextTests {

	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private final OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient)
		.build();

	private final Authentication principal = this.authorization.getAttribute(Principal.class.getName());

	private final OAuth2AuthorizationRequest authorizationRequest = this.authorization
		.getAttribute(OAuth2AuthorizationRequest.class.getName());

	private final OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication = new OAuth2AuthorizationConsentAuthenticationToken(
			this.authorizationRequest.getAuthorizationUri(), this.registeredClient.getClientId(), this.principal,
			"state", null, null);

	private final OAuth2AuthorizationConsent.Builder authorizationConsentBuilder = OAuth2AuthorizationConsent
		.withId(this.authorization.getRegisteredClientId(), this.authorization.getPrincipalName());

	@Test
	public void withWhenAuthenticationNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> OAuth2AuthorizationConsentAuthenticationContext.with(null))
			.withMessage("authentication cannot be null");
	}

	@Test
	public void setWhenValueNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationConsentAuthenticationContext.Builder builder = OAuth2AuthorizationConsentAuthenticationContext
			.with(this.authorizationConsentAuthentication);

		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.authorizationConsent(null));
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.registeredClient(null));
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.authorization(null));
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.authorizationRequest(null));
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.put(null, ""));
	}

	@Test
	public void buildWhenRequiredValueNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationConsentAuthenticationContext.Builder builder = OAuth2AuthorizationConsentAuthenticationContext
			.with(this.authorizationConsentAuthentication);

		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(builder::build)
			.withMessage("authorizationConsentBuilder cannot be null");
		builder.authorizationConsent(this.authorizationConsentBuilder);

		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(builder::build)
			.withMessage("registeredClient cannot be null");
		builder.registeredClient(this.registeredClient);

		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(builder::build)
			.withMessage("authorization cannot be null");
		builder.authorization(this.authorization);

		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(builder::build)
			.withMessage("authorizationRequest cannot be null");
		builder.authorizationRequest(this.authorizationRequest);

		builder.build();
	}

	@Test
	public void buildWhenAllValuesProvidedThenAllValuesAreSet() {
		OAuth2AuthorizationConsentAuthenticationContext context = OAuth2AuthorizationConsentAuthenticationContext
			.with(this.authorizationConsentAuthentication)
			.authorizationConsent(this.authorizationConsentBuilder)
			.registeredClient(this.registeredClient)
			.authorization(this.authorization)
			.authorizationRequest(this.authorizationRequest)
			.put("custom-key-1", "custom-value-1")
			.context((ctx) -> ctx.put("custom-key-2", "custom-value-2"))
			.build();

		assertThat(context.<Authentication>getAuthentication()).isEqualTo(this.authorizationConsentAuthentication);
		assertThat(context.getAuthorizationConsent()).isEqualTo(this.authorizationConsentBuilder);
		assertThat(context.getRegisteredClient()).isEqualTo(this.registeredClient);
		assertThat(context.getAuthorization()).isEqualTo(this.authorization);
		assertThat(context.getAuthorizationRequest()).isEqualTo(this.authorizationRequest);
		assertThat(context.<String>get("custom-key-1")).isEqualTo("custom-value-1");
		assertThat(context.<String>get("custom-key-2")).isEqualTo("custom-value-2");
	}

}
