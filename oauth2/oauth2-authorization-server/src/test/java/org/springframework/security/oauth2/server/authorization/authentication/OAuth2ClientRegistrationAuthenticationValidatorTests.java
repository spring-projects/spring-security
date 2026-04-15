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

import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link OAuth2ClientRegistrationAuthenticationValidator}. Exercises the
 * payloads from GHSA-qmmm-qvv5-j353 against the new {@code DEFAULT_*} validators and
 * confirms that the {@code SIMPLE_*} validators preserve the pre-fix behavior.
 *
 * @author addcontent
 */
public class OAuth2ClientRegistrationAuthenticationValidatorTests {

	private final OAuth2ClientRegistrationAuthenticationValidator validator = new OAuth2ClientRegistrationAuthenticationValidator();

	// --- redirect_uri: DEFAULT rejects CVE payloads ---

	@Test
	public void defaultRedirectUriValidatorWhenProtocolRelativeThenRejected() {
		assertRejected(context("//evil.example.com/steal", null),
				OAuth2ErrorCodes.INVALID_REDIRECT_URI, OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenJavascriptSchemeThenRejected() {
		assertRejected(context("javascript:alert(document.cookie)", null),
				OAuth2ErrorCodes.INVALID_REDIRECT_URI, OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenDataSchemeThenRejected() {
		assertRejected(context("data:text/html,<h1>xss</h1>", null),
				OAuth2ErrorCodes.INVALID_REDIRECT_URI, OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenVbscriptSchemeThenRejected() {
		assertRejected(context("vbscript:msgbox(\"xss\")", null),
				OAuth2ErrorCodes.INVALID_REDIRECT_URI, OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenFragmentThenRejected() {
		assertRejected(context("https://client.example.com/cb#evil", null),
				OAuth2ErrorCodes.INVALID_REDIRECT_URI, OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	// --- redirect_uri: DEFAULT accepts legitimate URIs ---

	@Test
	public void defaultRedirectUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException().isThrownBy(() -> validator.accept(context("https://client.example.com/cb", null)));
	}

	@Test
	public void defaultRedirectUriValidatorWhenCustomSchemeForNativeAppThenAccepted() {
		assertThatNoException().isThrownBy(() -> validator.accept(context("myapp://callback", null)));
	}

	@Test
	public void defaultRedirectUriValidatorWhenHttpLoopbackThenAccepted() {
		assertThatNoException().isThrownBy(() -> validator.accept(context("http://127.0.0.1:8080/cb", null)));
	}

	// --- jwks_uri: DEFAULT rejects http (SSRF vector) ---

	@Test
	public void defaultJwkSetUriValidatorWhenHttpThenRejected() {
		assertRejected(context("https://client.example.com/cb", "http://169.254.169.254/latest/meta-data/"),
				"invalid_client_metadata", OAuth2ClientMetadataClaimNames.JWKS_URI);
	}

	@Test
	public void defaultJwkSetUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException().isThrownBy(() -> validator
			.accept(context("https://client.example.com/cb", "https://client.example.com/jwks")));
	}

	@Test
	public void defaultJwkSetUriValidatorWhenAbsentThenAccepted() {
		assertThatNoException().isThrownBy(() -> validator.accept(context("https://client.example.com/cb", null)));
	}

	// --- scope: DEFAULT rejects any non-empty scope (tentative, pending jgrandja
	// confirmation) ---

	@Test
	public void defaultScopeValidatorWhenNonEmptyThenRejected() {
		OAuth2ClientRegistrationAuthenticationContext ctx = OAuth2ClientRegistrationAuthenticationContext
			.with(new OAuth2ClientRegistrationAuthenticationToken(null,
					OAuth2ClientRegistration.builder().redirectUri("https://client.example.com/cb").scope("admin").build()))
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> validator.accept(ctx))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE));
	}

	@Test
	public void defaultScopeValidatorWhenEmptyThenAccepted() {
		assertThatNoException().isThrownBy(() -> validator.accept(context("https://client.example.com/cb", null)));
	}

	// --- SIMPLE validators preserve pre-fix behavior ---

	@Test
	public void simpleRedirectUriValidatorWhenProtocolRelativeThenAccepted() {
		OAuth2ClientRegistrationAuthenticationContext ctx = context("//evil.example.com/steal", null);
		assertThatNoException().isThrownBy(
				() -> OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_REDIRECT_URI_VALIDATOR.accept(ctx));
	}

	@Test
	public void simpleRedirectUriValidatorWhenJavascriptThenAccepted() {
		OAuth2ClientRegistrationAuthenticationContext ctx = context("javascript:alert(1)", null);
		assertThatNoException().isThrownBy(
				() -> OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_REDIRECT_URI_VALIDATOR.accept(ctx));
	}

	@Test
	public void simpleJwkSetUriValidatorWhenHttpThenAccepted() {
		OAuth2ClientRegistrationAuthenticationContext ctx = context("https://client.example.com/cb",
				"http://169.254.169.254/latest/meta-data/");
		assertThatNoException().isThrownBy(
				() -> OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_JWK_SET_URI_VALIDATOR.accept(ctx));
	}

	@Test
	public void simpleScopeValidatorWhenNonEmptyThenAccepted() {
		OAuth2ClientRegistrationAuthenticationContext ctx = OAuth2ClientRegistrationAuthenticationContext
			.with(new OAuth2ClientRegistrationAuthenticationToken(null,
					OAuth2ClientRegistration.builder().redirectUri("https://client.example.com/cb").scope("admin").build()))
			.build();
		assertThatNoException().isThrownBy(
				() -> OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR.accept(ctx));
	}

	// --- Composition: DEFAULT URIs + SIMPLE scope allows legitimate DCR ---

	@Test
	public void composedValidatorWhenDefaultUrisAndSimpleScopeThenAcceptsLegitimateRequest() {
		Consumer<OAuth2ClientRegistrationAuthenticationContext> composed = OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
			.andThen(OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR)
			.andThen(OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR);
		OAuth2ClientRegistrationAuthenticationContext ctx = OAuth2ClientRegistrationAuthenticationContext
			.with(new OAuth2ClientRegistrationAuthenticationToken(null,
					OAuth2ClientRegistration.builder()
						.redirectUri("https://client.example.com/cb")
						.jwkSetUrl("https://client.example.com/jwks")
						.scope("openid")
						.scope("profile")
						.build()))
			.build();
		assertThatNoException().isThrownBy(() -> composed.accept(ctx));
	}

	// --- helpers ---

	private static OAuth2ClientRegistrationAuthenticationContext context(String redirectUri, String jwkSetUrl) {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder();
		if (redirectUri != null) {
			builder.redirectUri(redirectUri);
		}
		if (jwkSetUrl != null) {
			builder.jwkSetUrl(jwkSetUrl);
		}
		return OAuth2ClientRegistrationAuthenticationContext
			.with(new OAuth2ClientRegistrationAuthenticationToken(null, builder.build()))
			.build();
	}

	private void assertRejected(OAuth2ClientRegistrationAuthenticationContext ctx, String errorCode,
			String fieldName) {
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> validator.accept(ctx))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(errorCode);
				assertThat(error.getDescription()).contains(fieldName);
			});
	}

}
