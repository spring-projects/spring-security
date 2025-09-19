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

package org.springframework.security.oauth2.server.authorization.settings;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link AuthorizationServerSettings}.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 */
public class AuthorizationServerSettingsTests {

	@Test
	public void buildWhenDefaultThenDefaultsAreSet() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();

		assertThat(authorizationServerSettings.getIssuer()).isNull();
		assertThat(authorizationServerSettings.isMultipleIssuersAllowed()).isFalse();
		assertThat(authorizationServerSettings.getAuthorizationEndpoint()).isEqualTo("/oauth2/authorize");
		assertThat(authorizationServerSettings.getPushedAuthorizationRequestEndpoint()).isEqualTo("/oauth2/par");
		assertThat(authorizationServerSettings.getTokenEndpoint()).isEqualTo("/oauth2/token");
		assertThat(authorizationServerSettings.getJwkSetEndpoint()).isEqualTo("/oauth2/jwks");
		assertThat(authorizationServerSettings.getTokenRevocationEndpoint()).isEqualTo("/oauth2/revoke");
		assertThat(authorizationServerSettings.getTokenIntrospectionEndpoint()).isEqualTo("/oauth2/introspect");
		assertThat(authorizationServerSettings.getClientRegistrationEndpoint()).isEqualTo("/oauth2/register");
		assertThat(authorizationServerSettings.getOidcClientRegistrationEndpoint()).isEqualTo("/connect/register");
		assertThat(authorizationServerSettings.getOidcUserInfoEndpoint()).isEqualTo("/userinfo");
		assertThat(authorizationServerSettings.getOidcLogoutEndpoint()).isEqualTo("/connect/logout");
	}

	@Test
	public void buildWhenSettingsProvidedThenSet() {
		String authorizationEndpoint = "/oauth2/v1/authorize";
		String pushedAuthorizationRequestEndpoint = "/oauth2/v1/par";
		String tokenEndpoint = "/oauth2/v1/token";
		String jwkSetEndpoint = "/oauth2/v1/jwks";
		String tokenRevocationEndpoint = "/oauth2/v1/revoke";
		String tokenIntrospectionEndpoint = "/oauth2/v1/introspect";
		String clientRegistrationEndpoint = "/oauth2/v1/register";
		String oidcClientRegistrationEndpoint = "/connect/v1/register";
		String oidcUserInfoEndpoint = "/connect/v1/userinfo";
		String oidcLogoutEndpoint = "/connect/v1/logout";
		String issuer = "https://example.com:9000";

		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer(issuer)
			.authorizationEndpoint(authorizationEndpoint)
			.pushedAuthorizationRequestEndpoint(pushedAuthorizationRequestEndpoint)
			.tokenEndpoint(tokenEndpoint)
			.jwkSetEndpoint(jwkSetEndpoint)
			.tokenRevocationEndpoint(tokenRevocationEndpoint)
			.tokenIntrospectionEndpoint(tokenIntrospectionEndpoint)
			.tokenRevocationEndpoint(tokenRevocationEndpoint)
			.clientRegistrationEndpoint(clientRegistrationEndpoint)
			.oidcClientRegistrationEndpoint(oidcClientRegistrationEndpoint)
			.oidcUserInfoEndpoint(oidcUserInfoEndpoint)
			.oidcLogoutEndpoint(oidcLogoutEndpoint)
			.build();

		assertThat(authorizationServerSettings.getIssuer()).isEqualTo(issuer);
		assertThat(authorizationServerSettings.isMultipleIssuersAllowed()).isFalse();
		assertThat(authorizationServerSettings.getAuthorizationEndpoint()).isEqualTo(authorizationEndpoint);
		assertThat(authorizationServerSettings.getPushedAuthorizationRequestEndpoint())
			.isEqualTo(pushedAuthorizationRequestEndpoint);
		assertThat(authorizationServerSettings.getTokenEndpoint()).isEqualTo(tokenEndpoint);
		assertThat(authorizationServerSettings.getJwkSetEndpoint()).isEqualTo(jwkSetEndpoint);
		assertThat(authorizationServerSettings.getTokenRevocationEndpoint()).isEqualTo(tokenRevocationEndpoint);
		assertThat(authorizationServerSettings.getTokenIntrospectionEndpoint()).isEqualTo(tokenIntrospectionEndpoint);
		assertThat(authorizationServerSettings.getClientRegistrationEndpoint()).isEqualTo(clientRegistrationEndpoint);
		assertThat(authorizationServerSettings.getOidcClientRegistrationEndpoint())
			.isEqualTo(oidcClientRegistrationEndpoint);
		assertThat(authorizationServerSettings.getOidcUserInfoEndpoint()).isEqualTo(oidcUserInfoEndpoint);
		assertThat(authorizationServerSettings.getOidcLogoutEndpoint()).isEqualTo(oidcLogoutEndpoint);
	}

	@Test
	public void buildWhenIssuerSetAndMultipleIssuersAllowedTrueThenThrowIllegalArgumentException() {
		String issuer = "https://example.com:9000";
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().issuer(issuer).multipleIssuersAllowed(true).build())
			.withMessage(
					"The issuer identifier (" + issuer + ") cannot be set when isMultipleIssuersAllowed() is true.");
	}

	@Test
	public void buildWhenIssuerNotSetAndMultipleIssuersAllowedTrueThenDefaultsAreSet() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.multipleIssuersAllowed(true)
			.build();

		assertThat(authorizationServerSettings.getIssuer()).isNull();
		assertThat(authorizationServerSettings.isMultipleIssuersAllowed()).isTrue();
		assertThat(authorizationServerSettings.getAuthorizationEndpoint()).isEqualTo("/oauth2/authorize");
		assertThat(authorizationServerSettings.getPushedAuthorizationRequestEndpoint()).isEqualTo("/oauth2/par");
		assertThat(authorizationServerSettings.getTokenEndpoint()).isEqualTo("/oauth2/token");
		assertThat(authorizationServerSettings.getJwkSetEndpoint()).isEqualTo("/oauth2/jwks");
		assertThat(authorizationServerSettings.getTokenRevocationEndpoint()).isEqualTo("/oauth2/revoke");
		assertThat(authorizationServerSettings.getTokenIntrospectionEndpoint()).isEqualTo("/oauth2/introspect");
		assertThat(authorizationServerSettings.getClientRegistrationEndpoint()).isEqualTo("/oauth2/register");
		assertThat(authorizationServerSettings.getOidcClientRegistrationEndpoint()).isEqualTo("/connect/register");
		assertThat(authorizationServerSettings.getOidcUserInfoEndpoint()).isEqualTo("/userinfo");
		assertThat(authorizationServerSettings.getOidcLogoutEndpoint()).isEqualTo("/connect/logout");
	}

	@Test
	public void settingWhenCustomThenSet() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.setting("name1", "value1")
			.settings((settings) -> settings.put("name2", "value2"))
			.build();

		assertThat(authorizationServerSettings.getSettings()).hasSize(15);
		assertThat(authorizationServerSettings.<String>getSetting("name1")).isEqualTo("value1");
		assertThat(authorizationServerSettings.<String>getSetting("name2")).isEqualTo("value2");
	}

	@Test
	public void issuerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> AuthorizationServerSettings.builder().issuer(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void authorizationEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().authorizationEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void pushedAuthorizationRequestEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().pushedAuthorizationRequestEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void tokenEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> AuthorizationServerSettings.builder().tokenEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void tokenRevocationEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().tokenRevocationEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void tokenIntrospectionEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().tokenIntrospectionEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void clientRegistrationEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().clientRegistrationEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void oidcClientRegistrationEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().oidcClientRegistrationEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void oidcUserInfoEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().oidcUserInfoEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void jwksEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().jwkSetEndpoint(null))
			.withMessage("value cannot be null");
	}

	@Test
	public void oidcLogoutEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AuthorizationServerSettings.builder().oidcLogoutEndpoint(null))
			.withMessage("value cannot be null");
	}

}
