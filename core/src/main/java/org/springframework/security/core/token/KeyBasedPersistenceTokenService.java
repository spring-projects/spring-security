/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.core.token;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Basic implementation of {@link TokenService} that is compatible with clusters and
 * across machine restarts, without requiring database persistence.
 *
 * <p>
 * Keys are produced in the format:
 * </p>
 *
 * <p>
 * Base64(creationTime + ":" + hex(pseudoRandomNumber) + ":" + extendedInformation + ":" +
 * Sha512Hex(creationTime + ":" + hex(pseudoRandomNumber) + ":" + extendedInformation +
 * ":" + serverSecret) )
 * </p>
 *
 * <p>
 * In the above, <code>creationTime</code>, <code>tokenKey</code> and
 * <code>extendedInformation</code> are equal to that stored in {@link Token}. The
 * <code>Sha512Hex</code> includes the same payload, plus a <code>serverSecret</code>.
 * </p>
 *
 * <p>
 * The <code>serverSecret</code> varies every millisecond. It relies on two static
 * server-side secrets. The first is a password, and the second is a server integer. Both
 * of these must remain the same for any issued keys to subsequently be recognised. The
 * applicable <code>serverSecret</code> in any millisecond is computed by
 * <code>password</code> + ":" + (<code>creationTime</code> % <code>serverInteger</code>).
 * This approach further obfuscates the actual server secret and renders attempts to
 * compute the server secret more limited in usefulness (as any false tokens would be
 * forced to have a <code>creationTime</code> equal to the computed hash). Recall that
 * framework features depending on token services should reject tokens that are relatively
 * old in any event.
 * </p>
 *
 * <p>
 * A further consideration of this class is the requirement for cryptographically strong
 * pseudo-random numbers. To this end, the use of {@link SecureRandomFactoryBean} is
 * recommended to inject the property.
 * </p>
 *
 * <p>
 * This implementation uses UTF-8 encoding internally for string manipulation.
 * </p>
 *
 * @author Ben Alex
 *
 */
public class KeyBasedPersistenceTokenService implements TokenService, InitializingBean {
	private int pseudoRandomNumberBytes = 32;
	private String serverSecret;
	private Integer serverInteger;
	private SecureRandom secureRandom;

	public Token allocateToken(String extendedInformation) {
		Assert.notNull(extendedInformation,
				"Must provided non-null extendedInformation (but it can be empty)");
		long creationTime = new Date().getTime();
		String serverSecret = computeServerSecretApplicableAt(creationTime);
		String pseudoRandomNumber = generatePseudoRandomNumber();
		String content = Long.toString(creationTime) + ":" + pseudoRandomNumber + ":"
				+ extendedInformation;

		// Compute key
		String sha512Hex = Sha512DigestUtils.shaHex(content + ":" + serverSecret);
		String keyPayload = content + ":" + sha512Hex;
		String key = Utf8.decode(Base64.getEncoder().encode(Utf8.encode(keyPayload)));

		return new DefaultToken(key, creationTime, extendedInformation);
	}

	public Token verifyToken(String key) {
		if (key == null || "".equals(key)) {
			return null;
		}
		String[] tokens = StringUtils.delimitedListToStringArray(
				Utf8.decode(Base64.getDecoder().decode(Utf8.encode(key))), ":");
		Assert.isTrue(tokens.length >= 4, () -> "Expected 4 or more tokens but found "
				+ tokens.length);

		long creationTime;
		try {
			creationTime = Long.decode(tokens[0]);
		}
		catch (NumberFormatException nfe) {
			throw new IllegalArgumentException("Expected number but found " + tokens[0]);
		}

		String serverSecret = computeServerSecretApplicableAt(creationTime);
		String pseudoRandomNumber = tokens[1];

		// Permit extendedInfo to itself contain ":" characters
		StringBuilder extendedInfo = new StringBuilder();
		for (int i = 2; i < tokens.length - 1; i++) {
			if (i > 2) {
				extendedInfo.append(":");
			}
			extendedInfo.append(tokens[i]);
		}

		String sha1Hex = tokens[tokens.length - 1];

		// Verification
		String content = Long.toString(creationTime) + ":" + pseudoRandomNumber + ":"
				+ extendedInfo.toString();
		String expectedSha512Hex = Sha512DigestUtils.shaHex(content + ":" + serverSecret);
		Assert.isTrue(expectedSha512Hex.equals(sha1Hex), "Key verification failure");

		return new DefaultToken(key, creationTime, extendedInfo.toString());
	}

	/**
	 * @return a pseduo random number (hex encoded)
	 */
	private String generatePseudoRandomNumber() {
		byte[] randomBytes = new byte[pseudoRandomNumberBytes];
		secureRandom.nextBytes(randomBytes);
		return new String(Hex.encode(randomBytes));
	}

	private String computeServerSecretApplicableAt(long time) {
		return serverSecret + ":" + new Long(time % serverInteger).intValue();
	}

	/**
	 * @param serverSecret the new secret, which can contain a ":" if desired (never being
	 * sent to the client)
	 */
	public void setServerSecret(String serverSecret) {
		this.serverSecret = serverSecret;
	}

	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}

	/**
	 * @param pseudoRandomNumberBytes changes the number of bytes issued (must be &gt;= 0;
	 * defaults to 256)
	 */
	public void setPseudoRandomNumberBytes(int pseudoRandomNumberBytes) {
		Assert.isTrue(pseudoRandomNumberBytes >= 0,
				"Must have a positive pseudo random number bit size");
		this.pseudoRandomNumberBytes = pseudoRandomNumberBytes;
	}

	public void setServerInteger(Integer serverInteger) {
		this.serverInteger = serverInteger;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.hasText(serverSecret, "Server secret required");
		Assert.notNull(serverInteger, "Server integer required");
		Assert.notNull(secureRandom, "SecureRandom instance required");
	}
}
