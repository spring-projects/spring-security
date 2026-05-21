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
 * Tests for {@link OAuth2ClientRegistrationAuthenticationValidator}.
 *
 * @author addcontent
 */
public class OAuth2ClientRegistrationAuthenticationValidatorTests {

	private final OAuth2ClientRegistrationAuthenticationValidator validator = new OAuth2ClientRegistrationAuthenticationValidator();

	@Test
	public void defaultRedirectUriValidatorWhenProtocolRelativeThenRejected() {
		assertRejected(context("//client.example.com/path", null), OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenJavascriptSchemeThenRejected() {
		assertRejected(context("javascript:alert(document.cookie)", null), OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenDataSchemeThenRejected() {
		assertRejected(context("data:text/html,<h1>content</h1>", null), OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenVbscriptSchemeThenRejected() {
		assertRejected(context("vbscript:msgbox(\"content\")", null), OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenFragmentThenRejected() {
		assertRejected(context("https://client.example.com/cb#fragment", null), OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException().isThrownBy(() -> this.validator.accept(context("https://client.example.com", null)));
	}

	@Test
	public void defaultRedirectUriValidatorWhenCustomSchemeForNativeAppThenAccepted() {
		assertThatNoException().isThrownBy(() -> this.validator.accept(context("myapp://callback", null)));
	}

	@Test
	public void defaultRedirectUriValidatorWhenHttpLoopbackThenAccepted() {
		assertThatNoException().isThrownBy(() -> this.validator.accept(context("http://127.0.0.1:8080", null)));
	}

	@Test
	public void defaultJwkSetUriValidatorWhenHttpThenRejected() {
		assertRejected(context("https://client.example.com", "http://169.254.169.254/keys"), "invalid_client_metadata",
				OAuth2ClientMetadataClaimNames.JWKS_URI);
	}

	@Test
	public void defaultJwkSetUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException().isThrownBy(
				() -> this.validator.accept(context("https://client.example.com", "https://client.example.com/jwks")));
	}

	@Test
	public void defaultJwkSetUriValidatorWhenAbsentThenAccepted() {
		assertThatNoException().isThrownBy(() -> this.validator.accept(context("https://client.example.com", null)));
	}

	@Test
	public void defaultScopeValidatorWhenNonEmptyThenRejected() {
		OAuth2ClientRegistrationAuthenticationContext context = OAuth2ClientRegistrationAuthenticationContext
			.with(new OAuth2ClientRegistrationAuthenticationToken(null,
					OAuth2ClientRegistration.builder()
						.redirectUri("https://client.example.com")
						.scope("write")
						.build()))
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.validator.accept(context))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE));
	}

	@Test
	public void defaultScopeValidatorWhenEmptyThenAccepted() {
		assertThatNoException().isThrownBy(() -> this.validator.accept(context("https://client.example.com", null)));
	}

	@Test
	public void simpleRedirectUriValidatorWhenProtocolRelativeThenAccepted() {
		OAuth2ClientRegistrationAuthenticationContext context = context("//client.example.com/path", null);
		assertThatNoException().isThrownBy(
				() -> OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_REDIRECT_URI_VALIDATOR.accept(context));
	}

	@Test
	public void simpleRedirectUriValidatorWhenJavascriptThenAccepted() {
		OAuth2ClientRegistrationAuthenticationContext context = context("javascript:alert(document.cookie)", null);
		assertThatNoException().isThrownBy(
				() -> OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_REDIRECT_URI_VALIDATOR.accept(context));
	}

	@Test
	public void simpleJwkSetUriValidatorWhenHttpThenAccepted() {
		OAuth2ClientRegistrationAuthenticationContext context = context("https://client.example.com",
				"http://169.254.169.254/keys");
		assertThatNoException().isThrownBy(
				() -> OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_JWK_SET_URI_VALIDATOR.accept(context));
	}

	@Test
	public void simpleScopeValidatorWhenNonEmptyThenAccepted() {
		OAuth2ClientRegistrationAuthenticationContext context = OAuth2ClientRegistrationAuthenticationContext
			.with(new OAuth2ClientRegistrationAuthenticationToken(null,
					OAuth2ClientRegistration.builder()
						.redirectUri("https://client.example.com")
						.scope("write")
						.build()))
			.build();
		assertThatNoException()
			.isThrownBy(() -> OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR.accept(context));
	}

	@Test
	public void composedValidatorWhenDefaultUrisAndSimpleScopeThenAcceptsLegitimateRequest() {
		Consumer<OAuth2ClientRegistrationAuthenticationContext> composed = OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
			.andThen(OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR)
			.andThen(OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR);
		OAuth2ClientRegistrationAuthenticationContext context = OAuth2ClientRegistrationAuthenticationContext
			.with(new OAuth2ClientRegistrationAuthenticationToken(null,
					OAuth2ClientRegistration.builder()
						.redirectUri("https://client.example.com")
						.jwkSetUrl("https://client.example.com/jwks")
						.scope("openid")
						.scope("profile")
						.build()))
			.build();
		assertThatNoException().isThrownBy(() -> composed.accept(context));
	}

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

	private void assertRejected(OAuth2ClientRegistrationAuthenticationContext context, String errorCode,
			String fieldName) {
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.validator.accept(context))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(errorCode);
				assertThat(error.getDescription()).contains(fieldName);
			});
	}

}
