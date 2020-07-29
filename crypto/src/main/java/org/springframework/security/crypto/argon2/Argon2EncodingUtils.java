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

package org.springframework.security.crypto.argon2;

import java.util.Base64;

import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;

/**
 * Utility for encoding and decoding Argon2 hashes.
 *
 * Used by {@link Argon2PasswordEncoder}.
 *
 * @author Simeon Macke
 * @since 5.3
 */
class Argon2EncodingUtils {

	private static final Base64.Encoder b64encoder = Base64.getEncoder().withoutPadding();

	private static final Base64.Decoder b64decoder = Base64.getDecoder();

	/**
	 * Encodes a raw Argon2-hash and its parameters into the standard Argon2-hash-string
	 * as specified in the reference implementation
	 * (https://github.com/P-H-C/phc-winner-argon2/blob/master/src/encoding.c#L244):
	 *
	 * {@code $argon2<T>[$v=<num>]$m=<num>,t=<num>,p=<num>$<bin>$<bin>}
	 *
	 * where {@code <T>} is either 'd', 'id', or 'i', {@code <num>} is a decimal integer
	 * (positive, fits in an 'unsigned long'), and {@code <bin>} is Base64-encoded data
	 * (no '=' padding characters, no newline or whitespace).
	 *
	 * The last two binary chunks (encoded in Base64) are, in that order, the salt and the
	 * output. If no salt has been used, the salt will be omitted.
	 * @param hash the raw Argon2 hash in binary format
	 * @param parameters the Argon2 parameters that were used to create the hash
	 * @return the encoded Argon2-hash-string as described above
	 * @throws IllegalArgumentException if the Argon2Parameters are invalid
	 */
	public static String encode(byte[] hash, Argon2Parameters parameters) throws IllegalArgumentException {
		StringBuilder stringBuilder = new StringBuilder();

		switch (parameters.getType()) {
		case Argon2Parameters.ARGON2_d:
			stringBuilder.append("$argon2d");
			break;
		case Argon2Parameters.ARGON2_i:
			stringBuilder.append("$argon2i");
			break;
		case Argon2Parameters.ARGON2_id:
			stringBuilder.append("$argon2id");
			break;
		default:
			throw new IllegalArgumentException("Invalid algorithm type: " + parameters.getType());
		}
		stringBuilder.append("$v=").append(parameters.getVersion()).append("$m=").append(parameters.getMemory())
				.append(",t=").append(parameters.getIterations()).append(",p=").append(parameters.getLanes());

		if (parameters.getSalt() != null) {
			stringBuilder.append("$").append(b64encoder.encodeToString(parameters.getSalt()));
		}

		stringBuilder.append("$").append(b64encoder.encodeToString(hash));

		return stringBuilder.toString();
	}

	/**
	 * Decodes an Argon2 hash string as specified in the reference implementation
	 * (https://github.com/P-H-C/phc-winner-argon2/blob/master/src/encoding.c#L244) into
	 * the raw hash and the used parameters.
	 *
	 * The hash has to be formatted as follows:
	 * {@code $argon2<T>[$v=<num>]$m=<num>,t=<num>,p=<num>$<bin>$<bin>}
	 *
	 * where {@code <T>} is either 'd', 'id', or 'i', {@code <num>} is a decimal integer
	 * (positive, fits in an 'unsigned long'), and {@code <bin>} is Base64-encoded data
	 * (no '=' padding characters, no newline or whitespace).
	 *
	 * The last two binary chunks (encoded in Base64) are, in that order, the salt and the
	 * output. Both are required. The binary salt length and the output length must be in
	 * the allowed ranges defined in argon2.h.
	 * @param encodedHash the Argon2 hash string as described above
	 * @return an {@link Argon2Hash} object containing the raw hash and the
	 * {@link Argon2Parameters}.
	 * @throws IllegalArgumentException if the encoded hash is malformed
	 */
	public static Argon2Hash decode(String encodedHash) throws IllegalArgumentException {
		Argon2Parameters.Builder paramsBuilder;

		String[] parts = encodedHash.split("\\$");

		if (parts.length < 4) {
			throw new IllegalArgumentException("Invalid encoded Argon2-hash");
		}

		int currentPart = 1;

		switch (parts[currentPart++]) {
		case "argon2d":
			paramsBuilder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_d);
			break;
		case "argon2i":
			paramsBuilder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i);
			break;
		case "argon2id":
			paramsBuilder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id);
			break;
		default:
			throw new IllegalArgumentException("Invalid algorithm type: " + parts[0]);
		}

		if (parts[currentPart].startsWith("v=")) {
			paramsBuilder.withVersion(Integer.parseInt(parts[currentPart].substring(2)));
			currentPart++;
		}

		String[] performanceParams = parts[currentPart++].split(",");

		if (performanceParams.length != 3) {
			throw new IllegalArgumentException("Amount of performance parameters invalid");
		}

		if (performanceParams[0].startsWith("m=")) {
			paramsBuilder.withMemoryAsKB(Integer.parseInt(performanceParams[0].substring(2)));
		}
		else {
			throw new IllegalArgumentException("Invalid memory parameter");
		}

		if (performanceParams[1].startsWith("t=")) {
			paramsBuilder.withIterations(Integer.parseInt(performanceParams[1].substring(2)));
		}
		else {
			throw new IllegalArgumentException("Invalid iterations parameter");
		}

		if (performanceParams[2].startsWith("p=")) {
			paramsBuilder.withParallelism(Integer.parseInt(performanceParams[2].substring(2)));
		}
		else {
			throw new IllegalArgumentException("Invalid parallelity parameter");
		}

		paramsBuilder.withSalt(b64decoder.decode(parts[currentPart++]));

		return new Argon2Hash(b64decoder.decode(parts[currentPart]), paramsBuilder.build());
	}

	public static class Argon2Hash {

		private byte[] hash;

		private Argon2Parameters parameters;

		Argon2Hash(byte[] hash, Argon2Parameters parameters) {
			this.hash = Arrays.clone(hash);
			this.parameters = parameters;
		}

		public byte[] getHash() {
			return Arrays.clone(this.hash);
		}

		public void setHash(byte[] hash) {
			this.hash = Arrays.clone(hash);
		}

		public Argon2Parameters getParameters() {
			return this.parameters;
		}

		public void setParameters(Argon2Parameters parameters) {
			this.parameters = parameters;
		}

	}

}
