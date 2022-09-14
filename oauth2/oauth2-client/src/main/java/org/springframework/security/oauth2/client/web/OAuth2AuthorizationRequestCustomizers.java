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

package org.springframework.security.oauth2.client.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;

/**
 * A factory of customizers that customize the {@link OAuth2AuthorizationRequest OAuth 2.0
 * Authorization Request} via the {@link OAuth2AuthorizationRequest.Builder}.
 *
 * @author Joe Grandja
 * @since 5.7
 * @see OAuth2AuthorizationRequest.Builder
 * @see DefaultOAuth2AuthorizationRequestResolver#setAuthorizationRequestCustomizer(Consumer)
 * @see DefaultServerOAuth2AuthorizationRequestResolver#setAuthorizationRequestCustomizer(Consumer)
 */
public final class OAuth2AuthorizationRequestCustomizers {

	private static final StringKeyGenerator DEFAULT_SECURE_KEY_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	private OAuth2AuthorizationRequestCustomizers() {
	}

	/**
	 * Returns a {@code Consumer} to be provided the
	 * {@link OAuth2AuthorizationRequest.Builder} that adds the
	 * {@link PkceParameterNames#CODE_CHALLENGE code_challenge} and, usually,
	 * {@link PkceParameterNames#CODE_CHALLENGE_METHOD code_challenge_method} parameters
	 * to the OAuth 2.0 Authorization Request. The {@code code_verifier} is stored in
	 * {@link OAuth2AuthorizationRequest#getAttribute(String)} under the key
	 * {@link PkceParameterNames#CODE_VERIFIER code_verifier} for subsequent use in the
	 * OAuth 2.0 Access Token Request.
	 * @return a {@code Consumer} to be provided the
	 * {@link OAuth2AuthorizationRequest.Builder} that adds the PKCE parameters
	 * @see <a target="_blank" href=
	 * "https://datatracker.ietf.org/doc/html/rfc7636#section-1.1">1.1. Protocol Flow</a>
	 * @see <a target="_blank" href=
	 * "https://datatracker.ietf.org/doc/html/rfc7636#section-4.1">4.1. Client Creates a
	 * Code Verifier</a>
	 * @see <a target="_blank" href=
	 * "https://datatracker.ietf.org/doc/html/rfc7636#section-4.2">4.2. Client Creates the
	 * Code Challenge</a>
	 */
	public static Consumer<OAuth2AuthorizationRequest.Builder> withPkce() {
		return OAuth2AuthorizationRequestCustomizers::applyPkce;
	}

	private static void applyPkce(OAuth2AuthorizationRequest.Builder builder) {
		if (isPkceAlreadyApplied(builder)) {
			return;
		}

		String codeVerifier = DEFAULT_SECURE_KEY_GENERATOR.generateKey();

		builder.attributes((attrs) -> attrs.put(PkceParameterNames.CODE_VERIFIER, codeVerifier));

		builder.additionalParameters((params) -> {
			try {
				String codeChallenge = createHash(codeVerifier);
				params.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
				params.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
			}
			catch (NoSuchAlgorithmException ex) {
				params.put(PkceParameterNames.CODE_CHALLENGE, codeVerifier);
			}
		});
	}

	private static boolean isPkceAlreadyApplied(OAuth2AuthorizationRequest.Builder builder) {
		AtomicBoolean pkceApplied = new AtomicBoolean(false);
		builder.additionalParameters((params) -> {
			if (params.containsKey(PkceParameterNames.CODE_CHALLENGE)) {
				pkceApplied.set(true);
			}
		});
		return pkceApplied.get();
	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
