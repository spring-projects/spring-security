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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.Test;

/**
 * @author Simeon Macke
 */
public class Argon2EncodingUtilsTests {

	private final Base64.Decoder decoder = Base64.getDecoder();

	private TestDataEntry testDataEntry1 = new TestDataEntry(
			"$argon2i$v=19$m=1024,t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs",
			new Argon2EncodingUtils.Argon2Hash(decoder.decode("cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"),
					(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i)).withVersion(19).withMemoryAsKB(1024)
							.withIterations(3).withParallelism(2).withSalt("cRdFbCw23gz2Mlxk".getBytes()).build()));

	private TestDataEntry testDataEntry2 = new TestDataEntry(
			"$argon2id$v=19$m=333,t=5,p=2$JDR8N3k1QWx0$+PrEoHOHsWkU9lnsxqnOFrWTVEuOh7ZRIUIbe2yUG8FgTYNCWJfHQI09JAAFKzr2JAvoejEpTMghUt0WsntQYA",
			new Argon2EncodingUtils.Argon2Hash(
					decoder.decode(
							"+PrEoHOHsWkU9lnsxqnOFrWTVEuOh7ZRIUIbe2yUG8FgTYNCWJfHQI09JAAFKzr2JAvoejEpTMghUt0WsntQYA"),
					(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)).withVersion(19).withMemoryAsKB(333)
							.withIterations(5).withParallelism(2).withSalt("$4|7y5Alt".getBytes()).build()));

	@Test
	public void decodeWhenValidEncodedHashWithIThenDecodeCorrectly() {
		assertArgon2HashEquals(testDataEntry1.decoded, Argon2EncodingUtils.decode(testDataEntry1.encoded));
	}

	@Test
	public void decodeWhenValidEncodedHashWithIDThenDecodeCorrectly() {
		assertArgon2HashEquals(testDataEntry2.decoded, Argon2EncodingUtils.decode(testDataEntry2.encoded));
	}

	@Test
	public void encodeWhenValidArgumentsWithIThenEncodeToCorrectHash() {
		assertThat(Argon2EncodingUtils.encode(testDataEntry1.decoded.getHash(), testDataEntry1.decoded.getParameters()))
				.isEqualTo(testDataEntry1.encoded);
	}

	@Test
	public void encodeWhenValidArgumentsWithID2ThenEncodeToCorrectHash() {
		assertThat(Argon2EncodingUtils.encode(testDataEntry2.decoded.getHash(), testDataEntry2.decoded.getParameters()))
				.isEqualTo(testDataEntry2.encoded);
	}

	@Test(expected = IllegalArgumentException.class)
	public void encodeWhenNonexistingAlgorithmThenThrowException() {
		Argon2EncodingUtils.encode(new byte[] { 0, 1, 2, 3 }, (new Argon2Parameters.Builder(3)).withVersion(19)
				.withMemoryAsKB(333).withIterations(5).withParallelism(2).build());
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenNotAnArgon2HashThenThrowException() {
		Argon2EncodingUtils.decode("notahash");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenNonexistingAlgorithmThenThrowException() {
		Argon2EncodingUtils.decode(
				"$argon2x$v=19$m=1024,t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenIllegalVersionParameterThenThrowException() {
		Argon2EncodingUtils.decode(
				"$argon2i$v=x$m=1024,t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenIllegalMemoryParameterThenThrowException() {
		Argon2EncodingUtils
				.decode("$argon2i$v=19$m=x,t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenIllegalIterationsParameterThenThrowException() {
		Argon2EncodingUtils.decode(
				"$argon2i$v=19$m=1024,t=x,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenIllegalParallelityParameterThenThrowException() {
		Argon2EncodingUtils.decode(
				"$argon2i$v=19$m=1024,t=3,p=x$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenMissingVersionParameterThenThrowException() {
		Argon2EncodingUtils
				.decode("$argon2i$m=1024,t=3,p=x$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenMissingMemoryParameterThenThrowException() {
		Argon2EncodingUtils
				.decode("$argon2i$v=19$t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenMissingIterationsParameterThenThrowException() {
		Argon2EncodingUtils
				.decode("$argon2i$v=19$m=1024,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	@Test(expected = IllegalArgumentException.class)
	public void decodeWhenMissingParallelityParameterThenThrowException() {
		Argon2EncodingUtils
				.decode("$argon2i$v=19$m=1024,t=3$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs");
	}

	private void assertArgon2HashEquals(Argon2EncodingUtils.Argon2Hash expected,
			Argon2EncodingUtils.Argon2Hash actual) {
		assertThat(actual.getHash()).isEqualTo(expected.getHash());
		assertThat(actual.getParameters().getSalt()).isEqualTo(expected.getParameters().getSalt());
		assertThat(actual.getParameters().getType()).isEqualTo(expected.getParameters().getType());
		assertThat(actual.getParameters().getVersion()).isEqualTo(expected.getParameters().getVersion());
		assertThat(actual.getParameters().getMemory()).isEqualTo(expected.getParameters().getMemory());
		assertThat(actual.getParameters().getIterations()).isEqualTo(expected.getParameters().getIterations());
		assertThat(actual.getParameters().getLanes()).isEqualTo(expected.getParameters().getLanes());
	}

	private static class TestDataEntry {

		String encoded;

		Argon2EncodingUtils.Argon2Hash decoded;

		TestDataEntry(String encoded, Argon2EncodingUtils.Argon2Hash decoded) {
			this.encoded = encoded;
			this.decoded = decoded;
		}

	}

}
