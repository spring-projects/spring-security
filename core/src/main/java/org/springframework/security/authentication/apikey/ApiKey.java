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

import java.io.Serial;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Function;
import java.util.random.RandomGenerator;

import org.springframework.util.Assert;

/**
 * API key that consists ID and secret parts.
 * <p>
 * ID part allows efficiently searching API key information in some storage, such as
 * relational database ({@link ApiKeySearchService} interface is used for this purpose).
 * API key ID should not be used alone as it's prune to timing attacks (storages cannot
 * use constant-time comparison because of efficiency requirements), so separate secret
 * part is used.
 * <p>
 * Secret part should be hashed before storing API key data just the same way as
 * passwords, except that API keys do not require using specific slow hashing algorithms
 * used for passwords (such BCrypt, Argon, etc.).
 *
 * @author Alexey Razinkov
 */
public final class ApiKey implements Serializable {

	@Serial
	private static final long serialVersionUID = 5948279771096057355L;

	public static final SecureRandom RND = new SecureRandom();

	public static final int DEFAULT_ID_BYTES_LENGTH = 16;

	public static final int DEFAULT_SECRET_BYTES_LENGTH = 16;

	public static ApiKey random() {
		return random(RND, DEFAULT_ID_BYTES_LENGTH, DEFAULT_SECRET_BYTES_LENGTH);
	}

	public static ApiKey random(final RandomGenerator random, final int idBytesLength, final int secretBytesLength) {
		Objects.requireNonNull(random);
		final byte[] idBytes = new byte[idBytesLength];
		final byte[] secretBytes = new byte[secretBytesLength];
		random.nextBytes(idBytes);
		random.nextBytes(secretBytes);
		return new ApiKey(idBytes, secretBytes);
	}

	public static ApiKey parse(final String value) {
		return parse(value, DEFAULT_ENCODER, DEFAULT_DECODER);
	}

	public static ApiKey parse(final String value, final Function<byte[], String> encoder,
			final Function<String, byte[]> decoder) {
		Assert.hasText(value, "API key must be provided");
		Objects.requireNonNull(encoder);
		Objects.requireNonNull(decoder);

		final String[] parts = value.split("_", -1);
		Assert.isTrue(parts.length == 2, "API key has invalid format");

		final String apiKeyId = parts[0];
		Assert.hasText(apiKeyId, "API key has invalid format");

		final String apiKeySecret = parts[1];
		Assert.hasText(apiKeySecret, "API key has invalid format");

		return new ApiKey(apiKeyId, decoder.apply(apiKeySecret), encoder);
	}

	private final String id;

	private final byte[] secret;

	private final Function<byte[], String> encoder;

	private ApiKey(final byte[] id, final byte[] secret) {
		this(DEFAULT_ENCODER.apply(id), secret, DEFAULT_ENCODER);
	}

	private ApiKey(final String id, final byte[] secret, final Function<byte[], String> encoder) {
		Assert.hasText(id, "API key ID cannot be empty");
		Assert.isTrue(secret != null && secret.length > 0, "API key secret required");
		Objects.requireNonNull(encoder);
		this.id = id;
		this.secret = Arrays.copyOf(secret, secret.length);
		this.encoder = encoder;
	}

	public String getId() {
		return this.id;
	}

	public byte[] getSecret() {
		return Arrays.copyOf(this.secret, this.secret.length);
	}

	public String asToken() {
		return this.id + '_' + this.encoder.apply(this.secret);
	}

	@Override
	public String toString() {
		return "DefaultApiKey{id='" + this.id + '}';
	}

	private static final Function<byte[], String> DEFAULT_ENCODER = Base64.getEncoder()
		.withoutPadding()::encodeToString;

	private static final Function<String, byte[]> DEFAULT_DECODER = Base64.getDecoder()::decode;

}
