/*
 * Copyright 2013-2024 the original author or authors.
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

package org.springframework.security.crypto.encrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Reads RSA key pairs using BC provider classes but without the need to specify a crypto
 * provider or have BC added as one.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
final class RsaKeyHelper {

	private static final Charset UTF8 = StandardCharsets.UTF_8;

	private static final String BEGIN = "-----BEGIN";

	private static final Pattern PEM_DATA = Pattern.compile(".*-----BEGIN (.*)-----(.*)-----END (.*)-----",
			Pattern.DOTALL);

	private static final byte[] PREFIX = new byte[] { 0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a' };

	private RsaKeyHelper() {
	}

	static KeyPair parseKeyPair(String pemData) {
		Matcher m = PEM_DATA.matcher(pemData.replaceAll("\n *", "").trim());

		if (!m.matches()) {
			try {
				RSAPublicKey publicValue = extractPublicKey(pemData);
				if (publicValue != null) {
					return new KeyPair(publicValue, null);
				}
			}
			catch (Exception ex) {
				// Ignore
			}
			throw new IllegalArgumentException("String is not PEM encoded data, nor a public key encoded for ssh");
		}

		String type = m.group(1);
		final byte[] content = base64Decode(m.group(2));

		PublicKey publicKey;
		PrivateKey privateKey = null;

		try {
			KeyFactory fact = KeyFactory.getInstance("RSA");
			switch (type) {
				case "RSA PRIVATE KEY" -> {
					ASN1Sequence seq = ASN1Sequence.getInstance(content);
					if (seq.size() != 9) {
						throw new IllegalArgumentException("Invalid RSA Private Key ASN1 sequence.");
					}
					org.bouncycastle.asn1.pkcs.RSAPrivateKey key = org.bouncycastle.asn1.pkcs.RSAPrivateKey
						.getInstance(seq);
					RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
					RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(key.getModulus(), key.getPublicExponent(),
							key.getPrivateExponent(), key.getPrime1(), key.getPrime2(), key.getExponent1(),
							key.getExponent2(), key.getCoefficient());
					publicKey = fact.generatePublic(pubSpec);
					privateKey = fact.generatePrivate(privSpec);
				}
				case "PUBLIC KEY" -> {
					KeySpec keySpec = new X509EncodedKeySpec(content);
					publicKey = fact.generatePublic(keySpec);
				}
				case "RSA PUBLIC KEY" -> {
					ASN1Sequence seq = ASN1Sequence.getInstance(content);
					org.bouncycastle.asn1.pkcs.RSAPublicKey key = org.bouncycastle.asn1.pkcs.RSAPublicKey
						.getInstance(seq);
					RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
					publicKey = fact.generatePublic(pubSpec);
				}
				default -> throw new IllegalArgumentException(type + " is not a supported format");
			}

			return new KeyPair(publicKey, privateKey);
		}
		catch (InvalidKeySpecException ex) {
			throw new RuntimeException(ex);
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static byte[] base64Decode(String string) {
		try {
			ByteBuffer bytes = UTF8.newEncoder().encode(CharBuffer.wrap(string));
			byte[] bytesCopy = new byte[bytes.limit()];
			System.arraycopy(bytes.array(), 0, bytesCopy, 0, bytes.limit());
			return Base64.getDecoder().decode(bytesCopy);
		}
		catch (CharacterCodingException ex) {
			throw new RuntimeException(ex);
		}
	}

	static String base64Encode(byte[] bytes) {
		try {
			return UTF8.newDecoder().decode(ByteBuffer.wrap(Base64.getEncoder().encode(bytes))).toString();
		}
		catch (CharacterCodingException ex) {
			throw new RuntimeException(ex);
		}
	}

	static KeyPair generateKeyPair() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			return keyGen.generateKeyPair();
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}

	}

	private static final Pattern SSH_PUB_KEY = Pattern.compile("ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)");

	private static RSAPublicKey extractPublicKey(String key) {

		Matcher m = SSH_PUB_KEY.matcher(key);

		if (m.matches()) {
			String alg = m.group(1);
			String encKey = m.group(2);
			// String id = m.group(3);

			if (!"rsa".equalsIgnoreCase(alg)) {
				throw new IllegalArgumentException("Only RSA is currently supported, but algorithm was " + alg);
			}

			return parseSSHPublicKey(encKey);
		}
		else if (!key.startsWith(BEGIN)) {
			// Assume it's the plain Base64 encoded ssh key without the
			// "ssh-rsa" at the start
			return parseSSHPublicKey(key);
		}

		return null;
	}

	static RSAPublicKey parsePublicKey(String key) {

		RSAPublicKey publicKey = extractPublicKey(key);

		if (publicKey != null) {
			return publicKey;
		}

		KeyPair kp = parseKeyPair(key);

		if (kp.getPublic() == null) {
			throw new IllegalArgumentException("Key data does not contain a public key");
		}

		return (RSAPublicKey) kp.getPublic();

	}

	static String encodePublicKey(RSAPublicKey key, String id) {
		StringWriter output = new StringWriter();
		output.append("ssh-rsa ");
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		try {
			stream.write(PREFIX);
			writeBigInteger(stream, key.getPublicExponent());
			writeBigInteger(stream, key.getModulus());
		}
		catch (IOException ex) {
			throw new IllegalStateException("Cannot encode key", ex);
		}
		output.append(base64Encode(stream.toByteArray()));
		output.append(" " + id);
		return output.toString();
	}

	private static RSAPublicKey parseSSHPublicKey(String encKey) {
		ByteArrayInputStream in = new ByteArrayInputStream(base64Decode(encKey));

		byte[] prefix = new byte[11];

		try {
			if (in.read(prefix) != 11 || !Arrays.equals(PREFIX, prefix)) {
				throw new IllegalArgumentException("SSH key prefix not found");
			}

			BigInteger e = new BigInteger(readBigInteger(in));
			BigInteger n = new BigInteger(readBigInteger(in));

			return createPublicKey(n, e);
		}
		catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	static RSAPublicKey createPublicKey(BigInteger n, BigInteger e) {
		try {
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static void writeBigInteger(ByteArrayOutputStream stream, BigInteger num) throws IOException {
		int length = num.toByteArray().length;
		byte[] data = new byte[4];
		data[0] = (byte) ((length >> 24) & 0xFF);
		data[1] = (byte) ((length >> 16) & 0xFF);
		data[2] = (byte) ((length >> 8) & 0xFF);
		data[3] = (byte) (length & 0xFF);
		stream.write(data);
		stream.write(num.toByteArray());
	}

	private static byte[] readBigInteger(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[4];

		if (in.read(b) != 4) {
			throw new IOException("Expected length data as 4 bytes");
		}

		int l = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);

		b = new byte[l];

		if (in.read(b) != l) {
			throw new IOException("Expected " + l + " key bytes");
		}

		return b;
	}

}
