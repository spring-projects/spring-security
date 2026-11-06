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

package org.springframework.security.oauth2.client.oidc.userinfo;

import java.security.Key;
import java.text.ParseException;
import java.util.function.Function;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.SecretJWK;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * A {@link JwtDecoder} that decrypts an encrypted JWT, which has to contain a signed JWT
 * (a nested JWT), before it delegates the verification and validation of the signed JWT
 * to another {@link JwtDecoder}. A JWT that is not encrypted is delegated as is.
 *
 * @author Sharang Gupta
 * @since 7.2
 */
final class JweDecryptingJwtDecoder implements JwtDecoder {

	private static final String MISSING_DECRYPTION_KEY_ERROR_CODE = "missing_decryption_key";

	private static final int COMPACT_JWE_PARTS = 5;

	private final DefaultJWEDecrypterFactory decrypterFactory = new DefaultJWEDecrypterFactory();

	private final JwtDecoder signatureVerifier;

	private final ClientRegistration clientRegistration;

	private final Function<ClientRegistration, @Nullable JWK> decryptionKeyResolver;

	JweDecryptingJwtDecoder(JwtDecoder signatureVerifier, ClientRegistration clientRegistration,
			Function<ClientRegistration, @Nullable JWK> decryptionKeyResolver) {
		this.signatureVerifier = signatureVerifier;
		this.clientRegistration = clientRegistration;
		this.decryptionKeyResolver = decryptionKeyResolver;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		if (!isEncrypted(token)) {
			return this.signatureVerifier.decode(token);
		}
		return this.signatureVerifier.decode(decrypt(token));
	}

	private boolean isEncrypted(String token) {
		try {
			return JOSEObject.split(token).length == COMPACT_JWE_PARTS;
		}
		catch (ParseException ex) {
			// let the delegate report the malformed token
			return false;
		}
	}

	private String decrypt(String token) {
		Key decryptionKey = getDecryptionKey();
		try {
			EncryptedJWT encryptedJwt = EncryptedJWT.parse(token);
			encryptedJwt.decrypt(this.decrypterFactory.createJWEDecrypter(encryptedJwt.getHeader(), decryptionKey));
			SignedJWT signedJwt = encryptedJwt.getPayload().toSignedJWT();
			if (signedJwt == null) {
				throw new BadJwtException("The decrypted UserInfo response does not contain a signed JWT");
			}
			return signedJwt.serialize();
		}
		catch (ParseException ex) {
			throw new BadJwtException("The encrypted UserInfo response is malformed", ex);
		}
		catch (JOSEException ex) {
			throw new BadJwtException("Failed to decrypt the UserInfo response: " + ex.getMessage(), ex);
		}
	}

	private Key getDecryptionKey() {
		JWK jwk = this.decryptionKeyResolver.apply(this.clientRegistration);
		if (jwk == null) {
			throw missingDecryptionKey("Failed to find a decryption key for Client Registration: '"
					+ this.clientRegistration.getRegistrationId()
					+ "'. Check to ensure you have configured a JWE decryption key resolver.");
		}
		Key key = null;
		try {
			if (jwk instanceof AsymmetricJWK asymmetricJwk) {
				key = asymmetricJwk.toPrivateKey();
			}
			else if (jwk instanceof SecretJWK secretJwk) {
				key = secretJwk.toSecretKey();
			}
		}
		catch (JOSEException ex) {
			throw missingDecryptionKey("The decryption key for Client Registration: '"
					+ this.clientRegistration.getRegistrationId() + "' is not supported: " + ex.getMessage());
		}
		if (key == null) {
			throw missingDecryptionKey("The decryption key for Client Registration: '"
					+ this.clientRegistration.getRegistrationId() + "' does not contain a private or secret key.");
		}
		return key;
	}

	private OAuth2AuthenticationException missingDecryptionKey(String description) {
		OAuth2Error oauth2Error = new OAuth2Error(MISSING_DECRYPTION_KEY_ERROR_CODE, description, null);
		return new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
	}

}
