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

package org.springframework.security.authentication.apikey;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;

/**
 * {@link ApiKeyDigest} implementation via SHA3-256.
 *
 * @author Alexey Razinkov
 */
public class Sha3ApiKeyDigest implements ApiKeyDigest {

	private static final Log log = LogFactory.getLog(Sha3ApiKeyDigest.class);

	private static final String CODE = "{sha3_256}";

	private final Function<byte[], String> encoder;

	private final Function<String, byte[]> decoder;

	public Sha3ApiKeyDigest() {
		this(Base64.getEncoder().withoutPadding()::encodeToString, Base64.getDecoder()::decode);
	}

	public Sha3ApiKeyDigest(Function<byte[], String> encoder, Function<String, byte[]> decoder) {
		this.encoder = Objects.requireNonNull(encoder);
		this.decoder = Objects.requireNonNull(decoder);
	}

	@Override
	public String digest(final byte[] apiKeySecret) {
		Objects.requireNonNull(apiKeySecret);
		final MessageDigest digest = createDigest();
		final byte[] secretHashBytes = digest.digest(apiKeySecret);
		final String secretHash = this.encoder.apply(secretHashBytes);
		return CODE + secretHash;
	}

	@Override
	public boolean matches(final byte[] apiKeySecret, final String hash) {
		Objects.requireNonNull(apiKeySecret);
		Objects.requireNonNull(hash);
		Assert.isTrue(hash.startsWith(CODE), "Hash must start with " + CODE);

		final MessageDigest digest = createDigest();
		final byte[] actualSecretHash = digest.digest(apiKeySecret);
		final String cleanHash = hash.substring(CODE.length());
		final byte[] expectedSecretHash = this.decoder.apply(cleanHash);
		return MessageDigest.isEqual(expectedSecretHash, actualSecretHash);
	}

	@Override
	public String getDummyDigest() {
		return this.encoder.apply(DummyHolder.VALUE);
	}

	private static MessageDigest createDigest() {
		try {
			return MessageDigest.getInstance("SHA3-256");
		}
		catch (final NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/**
	 * Holds lazily initialized dummy hash value.
	 */
	private static final class DummyHolder {

		private static final byte[] VALUE;

		static {
			log.debug("Creating dummy hash for mitigating timing attack");
			final MessageDigest digest = createDigest();
			final byte[] deadbeef = new byte[] { 0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF, };
			VALUE = digest.digest(deadbeef);
		}

	}

}
