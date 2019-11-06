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

package org.springframework.security.converter;

import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Base64;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;

/**
 * Used for creating {@link java.security.Key} converter instances
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class RsaKeyConverters {
	private static final String DASHES = "-----";
	private static final String PKCS8_PEM_HEADER = DASHES + "BEGIN PRIVATE KEY" + DASHES;
	private static final String PKCS8_PEM_FOOTER = DASHES + "END PRIVATE KEY" + DASHES;
	private static final String X509_PEM_HEADER = DASHES + "BEGIN PUBLIC KEY" + DASHES;
	private static final String X509_PEM_FOOTER = DASHES + "END PUBLIC KEY" + DASHES;

	/**
	 * Construct a {@link Converter} for converting a PEM-encoded PKCS#8 RSA Private Key
	 * into a {@link RSAPrivateKey}.
	 *
	 * Note that keys are often formatted in PKCS#1 and this can easily be identified by the header.
	 * If the key file begins with "-----BEGIN RSA PRIVATE KEY-----", then it is PKCS#1. If it is
	 * PKCS#8 formatted, then it begins with "-----BEGIN PRIVATE KEY-----".
	 *
	 * This converter does not close the {@link InputStream} in order to avoid making non-portable
	 * assumptions about the streams' origin and further use.
	 *
	 * @return A {@link Converter} that can read a PEM-encoded PKCS#8 RSA Private Key and return a
	 * {@link RSAPrivateKey}.
	 */
	public static Converter<InputStream, RSAPrivateKey> pkcs8() {
		KeyFactory keyFactory = rsaFactory();
		return source -> {
			List<String> lines = readAllLines(source);
			Assert.isTrue(!lines.isEmpty() && lines.get(0).startsWith(PKCS8_PEM_HEADER),
					"Key is not in PEM-encoded PKCS#8 format, " +
							"please check that the header begins with -----" + PKCS8_PEM_HEADER + "-----");
			StringBuilder base64Encoded = new StringBuilder();
			for (String line : lines) {
				if (RsaKeyConverters.isNotPkcs8Wrapper(line)) {
					base64Encoded.append(line);
				}
			}
			byte[] pkcs8 = Base64.getDecoder().decode(base64Encoded.toString());

			try {
				return (RSAPrivateKey) keyFactory.generatePrivate(
						new PKCS8EncodedKeySpec(pkcs8));
			} catch (Exception e) {
				throw new IllegalArgumentException(e);
			}
		};
	}

	/**
	 * Construct a {@link Converter} for converting a PEM-encoded X.509 RSA Public Key
	 * into a {@link RSAPublicKey}.
	 *
	 * This converter does not close the {@link InputStream} in order to avoid making non-portable
	 * assumptions about the streams' origin and further use.
	 *
	 * @return A {@link Converter} that can read a PEM-encoded X.509 RSA Public Key and return a
	 * {@link RSAPublicKey}.
	 */
	public static Converter<InputStream, RSAPublicKey> x509() {
		KeyFactory keyFactory = rsaFactory();
		return source -> {
			List<String> lines = readAllLines(source);
			Assert.isTrue(!lines.isEmpty() && lines.get(0).startsWith(X509_PEM_HEADER),
					"Key is not in PEM-encoded X.509 format, " +
							"please check that the header begins with -----" + X509_PEM_HEADER + "-----");
			StringBuilder base64Encoded = new StringBuilder();
			for (String line : lines) {
				if (RsaKeyConverters.isNotX509Wrapper(line)) {
					base64Encoded.append(line);
				}
			}
			byte[] x509 = Base64.getDecoder().decode(base64Encoded.toString());

			try {
				return (RSAPublicKey) keyFactory.generatePublic(
						new X509EncodedKeySpec(x509));
			} catch (Exception e) {
				throw new IllegalArgumentException(e);
			}
		};
	}

	private static List<String> readAllLines(InputStream source) {
		BufferedReader reader = new BufferedReader(new InputStreamReader(source));
		return reader.lines().collect(Collectors.toList());
	}

	private static KeyFactory rsaFactory() {
		try {
			return KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	private static boolean isNotPkcs8Wrapper(String line) {
		return !PKCS8_PEM_HEADER.equals(line) && !PKCS8_PEM_FOOTER.equals(line);
	}

	private static boolean isNotX509Wrapper(String line) {
		return !X509_PEM_HEADER.equals(line) && !X509_PEM_FOOTER.equals(line);
	}
}
