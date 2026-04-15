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

package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link OidcClientRegistrationAuthenticationValidator}. Exercises the payloads
 * from GHSA-qmmm-qvv5-j353 against the new {@code DEFAULT_*} validators and confirms
 * that the {@code SIMPLE_*} validators preserve the pre-fix behavior.
 *
 * @author addcontent
 */
public class OidcClientRegistrationAuthenticationValidatorTests {

	private final OidcClientRegistrationAuthenticationValidator validator = new OidcClientRegistrationAuthenticationValidator();

	// --- redirect_uri ---

	@Test
	public void defaultRedirectUriValidatorWhenProtocolRelativeThenRejected() {
		assertRejected(context("//evil.example.com/steal", null, null),
				OAuth2ErrorCodes.INVALID_REDIRECT_URI, OidcClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenJavascriptSchemeThenRejected() {
		assertRejected(context("javascript:alert(document.cookie)", null, null),
				OAuth2ErrorCodes.INVALID_REDIRECT_URI, OidcClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException()
			.isThrownBy(() -> validator.accept(context("https://client.example.com/cb", null, null)));
	}

	// --- post_logout_redirect_uri ---

	@Test
	public void defaultPostLogoutRedirectUriValidatorWhenJavascriptSchemeThenRejected() {
		assertRejected(context("https://client.example.com/cb", "javascript:alert(document.cookie)", null),
				"invalid_client_metadata", OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
	}

	@Test
	public void defaultPostLogoutRedirectUriValidatorWhenProtocolRelativeThenRejected() {
		assertRejected(context("https://client.example.com/cb", "//evil.example.com/post-logout", null),
				"invalid_client_metadata", OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
	}

	@Test
	public void defaultPostLogoutRedirectUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException().isThrownBy(
				() -> validator.accept(context("https://client.example.com/cb",
						"https://client.example.com/post-logout", null)));
	}

	// --- jwks_uri ---

	@Test
	public void defaultJwkSetUriValidatorWhenHttpThenRejected() {
		assertRejected(context("https://client.example.com/cb", null, "http://169.254.169.254/latest/meta-data/"),
				"invalid_client_metadata", OidcClientMetadataClaimNames.JWKS_URI);
	}

	@Test
	public void defaultJwkSetUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException().isThrownBy(() -> validator
			.accept(context("https://client.example.com/cb", null, "https://client.example.com/jwks")));
	}

	// --- scope ---

	@Test
	public void defaultScopeValidatorWhenNonEmptyThenRejected() {
		OidcClientRegistrationAuthenticationContext ctx = OidcClientRegistrationAuthenticationContext
			.with(new OidcClientRegistrationAuthenticationToken(principal(),
					OidcClientRegistration.builder().redirectUri("https://client.example.com/cb").scope("admin").build()))
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> validator.accept(ctx))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE));
	}

	// --- SIMPLE validators preserve pre-fix behavior ---

	@Test
	public void simpleRedirectUriValidatorWhenJavascriptThenAccepted() {
		OidcClientRegistrationAuthenticationContext ctx = context("javascript:alert(1)", null, null);
		assertThatNoException().isThrownBy(
				() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_REDIRECT_URI_VALIDATOR.accept(ctx));
	}

	@Test
	public void simplePostLogoutRedirectUriValidatorWhenJavascriptThenAccepted() {
		OidcClientRegistrationAuthenticationContext ctx = context("https://client.example.com/cb",
				"javascript:alert(1)", null);
		assertThatNoException().isThrownBy(() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_POST_LOGOUT_REDIRECT_URI_VALIDATOR
			.accept(ctx));
	}

	@Test
	public void simpleJwkSetUriValidatorWhenHttpThenAccepted() {
		OidcClientRegistrationAuthenticationContext ctx = context("https://client.example.com/cb", null,
				"http://169.254.169.254/latest/meta-data/");
		assertThatNoException().isThrownBy(
				() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_JWK_SET_URI_VALIDATOR.accept(ctx));
	}

	@Test
	public void simpleScopeValidatorWhenNonEmptyThenAccepted() {
		OidcClientRegistrationAuthenticationContext ctx = OidcClientRegistrationAuthenticationContext
			.with(new OidcClientRegistrationAuthenticationToken(principal(),
					OidcClientRegistration.builder().redirectUri("https://client.example.com/cb").scope("admin").build()))
			.build();
		assertThatNoException().isThrownBy(
				() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR.accept(ctx));
	}

	// --- Composition ---

	@Test
	public void composedValidatorWhenDefaultUrisAndSimpleScopeThenAcceptsLegitimateRequest() {
		Consumer<OidcClientRegistrationAuthenticationContext> composed = OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
			.andThen(OidcClientRegistrationAuthenticationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
			.andThen(OidcClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR)
			.andThen(OidcClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR);
		OidcClientRegistrationAuthenticationContext ctx = OidcClientRegistrationAuthenticationContext
			.with(new OidcClientRegistrationAuthenticationToken(principal(),
					OidcClientRegistration.builder()
						.redirectUri("https://client.example.com/cb")
						.postLogoutRedirectUri("https://client.example.com/post-logout")
						.jwkSetUrl("https://client.example.com/jwks")
						.scope("openid")
						.scope("profile")
						.build()))
			.build();
		assertThatNoException().isThrownBy(() -> composed.accept(ctx));
	}

	// --- helpers ---

	private static Authentication principal() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("user", "password", "SCOPE_client.create");
		principal.setAuthenticated(true);
		return principal;
	}

	private static OidcClientRegistrationAuthenticationContext context(String redirectUri,
			String postLogoutRedirectUri, String jwkSetUrl) {
		OidcClientRegistration.Builder builder = OidcClientRegistration.builder();
		if (redirectUri != null) {
			builder.redirectUri(redirectUri);
		}
		if (postLogoutRedirectUri != null) {
			builder.postLogoutRedirectUri(postLogoutRedirectUri);
		}
		if (jwkSetUrl != null) {
			builder.jwkSetUrl(jwkSetUrl);
		}
		return OidcClientRegistrationAuthenticationContext
			.with(new OidcClientRegistrationAuthenticationToken(principal(), builder.build()))
			.build();
	}

	private void assertRejected(OidcClientRegistrationAuthenticationContext ctx, String errorCode, String fieldName) {
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> validator.accept(ctx))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(errorCode);
				assertThat(error.getDescription()).contains(fieldName);
			});
	}

}
