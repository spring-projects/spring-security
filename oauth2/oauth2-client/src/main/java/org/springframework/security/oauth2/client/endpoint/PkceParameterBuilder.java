/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * A {@link Consumer} of {@link OAuth2AuthorizationRequest.Builder} that
 * adds additional {@link PkceParameterNames PKCE parameters}
 * for use in the OAuth 2.0 Authorization Request and Access Token Request.
 *
 * <p>
 * The {@link PkceParameterNames#CODE_CHALLENGE} and {@link PkceParameterNames#CODE_CHALLENGE_METHOD}
 * are added as {@link OAuth2AuthorizationRequest#getAdditionalParameters() additional parameters} in the Authorization Request.
 * The {@link PkceParameterNames#CODE_VERIFIER} is stored as an {@link OAuth2AuthorizationRequest#getAttributes() attribute}
 * for use in the Access Token Request.
 *
 * @author Stephen Doxsee
 * @author Kevin Bolduc
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizationRequest.Builder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636#section-1.1">Section 1.1 Protocol Flow</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636#section-4.1">Section 4.1 Client Creates a Code Verifier</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636#section-4.2">Section 4.2 Client Creates the Code Challenge</a>
 */
public final class PkceParameterBuilder implements BiConsumer<OAuth2AuthorizationRequest.Builder, ClientRegistration> {
	private final StringKeyGenerator codeVerifierGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

	@Override
	public void accept(OAuth2AuthorizationRequest.Builder builder, ClientRegistration clientRegistration) {
		if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			return;
		}

		String codeVerifier = this.codeVerifierGenerator.generateKey();
		builder.attributes(attrs -> attrs.put(PkceParameterNames.CODE_VERIFIER, codeVerifier));
		try {
			String codeChallenge = createCodeChallenge(codeVerifier);
			builder.additionalParameters(params -> {
				params.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
				params.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
			});
		} catch (NoSuchAlgorithmException ex) {
			builder.additionalParameters(params -> params.put(PkceParameterNames.CODE_CHALLENGE, codeVerifier));
		}
	}

	private String createCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}
}
