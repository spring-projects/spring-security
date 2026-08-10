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
 * Tests for {@link OidcClientRegistrationAuthenticationValidator}.
 *
 * @author addcontent
 */
public class OidcClientRegistrationAuthenticationValidatorTests {

	private final OidcClientRegistrationAuthenticationValidator validator = new OidcClientRegistrationAuthenticationValidator();

	@Test
	public void defaultRedirectUriValidatorWhenProtocolRelativeThenRejected() {
		assertRejected(context("//client.example.com/path", null, null), OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OidcClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenJavascriptSchemeThenRejected() {
		assertRejected(context("javascript:alert(document.cookie)", null, null), OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OidcClientMetadataClaimNames.REDIRECT_URIS);
	}

	@Test
	public void defaultRedirectUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException()
			.isThrownBy(() -> this.validator.accept(context("https://client.example.com", null, null)));
	}

	@Test
	public void defaultPostLogoutRedirectUriValidatorWhenJavascriptSchemeThenRejected() {
		assertRejected(context("https://client.example.com", "javascript:alert(document.cookie)", null),
				"invalid_client_metadata", OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
	}

	@Test
	public void defaultPostLogoutRedirectUriValidatorWhenProtocolRelativeThenRejected() {
		assertRejected(context("https://client.example.com", "//client.example.com/post-logout", null),
				"invalid_client_metadata", OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
	}

	@Test
	public void defaultPostLogoutRedirectUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException().isThrownBy(() -> this.validator
			.accept(context("https://client.example.com", "https://client.example.com/post-logout", null)));
	}

	@Test
	public void defaultJwkSetUriValidatorWhenHttpThenRejected() {
		assertRejected(context("https://client.example.com", null, "http://169.254.169.254/keys"),
				"invalid_client_metadata", OidcClientMetadataClaimNames.JWKS_URI);
	}

	@Test
	public void defaultJwkSetUriValidatorWhenHttpsThenAccepted() {
		assertThatNoException().isThrownBy(() -> this.validator
			.accept(context("https://client.example.com", null, "https://client.example.com/jwks")));
	}

	@Test
	public void defaultScopeValidatorWhenNonEmptyThenRejected() {
		OidcClientRegistrationAuthenticationContext context = OidcClientRegistrationAuthenticationContext
			.with(new OidcClientRegistrationAuthenticationToken(principal(),
					OidcClientRegistration.builder().redirectUri("https://client.example.com").scope("write").build()))
			.build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.validator.accept(context))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE));
	}

	@Test
	public void simpleRedirectUriValidatorWhenJavascriptThenAccepted() {
		OidcClientRegistrationAuthenticationContext context = context("javascript:alert(document.cookie)", null, null);
		assertThatNoException().isThrownBy(
				() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_REDIRECT_URI_VALIDATOR.accept(context));
	}

	@Test
	public void simplePostLogoutRedirectUriValidatorWhenJavascriptThenAccepted() {
		OidcClientRegistrationAuthenticationContext context = context("https://client.example.com",
				"javascript:alert(document.cookie)", null);
		assertThatNoException()
			.isThrownBy(() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_POST_LOGOUT_REDIRECT_URI_VALIDATOR
				.accept(context));
	}

	@Test
	public void simpleJwkSetUriValidatorWhenHttpThenAccepted() {
		OidcClientRegistrationAuthenticationContext ctx = context("https://client.example.com", null,
				"http://169.254.169.254/keys");
		assertThatNoException()
			.isThrownBy(() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_JWK_SET_URI_VALIDATOR.accept(ctx));
	}

	@Test
	public void simpleScopeValidatorWhenNonEmptyThenAccepted() {
		OidcClientRegistrationAuthenticationContext context = OidcClientRegistrationAuthenticationContext
			.with(new OidcClientRegistrationAuthenticationToken(principal(),
					OidcClientRegistration.builder().redirectUri("https://client.example.com").scope("write").build()))
			.build();
		assertThatNoException()
			.isThrownBy(() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR.accept(context));
	}

	@Test
	public void composedValidatorWhenDefaultUrisAndSimpleScopeThenAcceptsLegitimateRequest() {
		Consumer<OidcClientRegistrationAuthenticationContext> composed = OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
			.andThen(OidcClientRegistrationAuthenticationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
			.andThen(OidcClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR)
			.andThen(OidcClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR);
		OidcClientRegistrationAuthenticationContext context = OidcClientRegistrationAuthenticationContext
			.with(new OidcClientRegistrationAuthenticationToken(principal(),
					OidcClientRegistration.builder()
						.redirectUri("https://client.example.com")
						.postLogoutRedirectUri("https://client.example.com/post-logout")
						.jwkSetUrl("https://client.example.com/jwks")
						.scope("openid")
						.scope("profile")
						.build()))
			.build();
		assertThatNoException().isThrownBy(() -> composed.accept(context));
	}

	private static Authentication principal() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("user", "password");
		principal.setAuthenticated(true);
		return principal;
	}

	private static OidcClientRegistrationAuthenticationContext context(String redirectUri, String postLogoutRedirectUri,
			String jwkSetUrl) {
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

	private void assertRejected(OidcClientRegistrationAuthenticationContext context, String errorCode,
			String fieldName) {
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.validator.accept(context))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(errorCode);
				assertThat(error.getDescription()).contains(fieldName);
			});
	}

}
