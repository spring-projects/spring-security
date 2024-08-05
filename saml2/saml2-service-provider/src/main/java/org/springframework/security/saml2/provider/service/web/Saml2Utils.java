/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import org.springframework.security.saml2.Saml2Exception;

/**
 * Utility methods for working with serialized SAML messages.
 *
 * For internal use only.
 *
 * @author Josh Cummings
 */
final class Saml2Utils {

	private Saml2Utils() {
	}

	static String samlEncode(byte[] b) {
		return Base64.getEncoder().encodeToString(b);
	}

	static byte[] samlDecode(String s) {
		return Base64.getMimeDecoder().decode(s);
	}

	static byte[] samlDeflate(String s) {
		try {
			ByteArrayOutputStream b = new ByteArrayOutputStream();
			DeflaterOutputStream deflater = new DeflaterOutputStream(b, new Deflater(Deflater.DEFLATED, true));
			deflater.write(s.getBytes(StandardCharsets.UTF_8));
			deflater.finish();
			return b.toByteArray();
		}
		catch (IOException ex) {
			throw new Saml2Exception("Unable to deflate string", ex);
		}
	}

	static String samlInflate(byte[] b) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
			iout.write(b);
			iout.finish();
			return new String(out.toByteArray(), StandardCharsets.UTF_8);
		}
		catch (IOException ex) {
			throw new Saml2Exception("Unable to inflate string", ex);
		}
	}

	static EncodingConfigurer withDecoded(String decoded) {
		return new EncodingConfigurer(decoded);
	}

	static DecodingConfigurer withEncoded(String encoded) {
		return new DecodingConfigurer(encoded);
	}

	static final class EncodingConfigurer {

		private final String decoded;

		private boolean deflate;

		private EncodingConfigurer(String decoded) {
			this.decoded = decoded;
		}

		EncodingConfigurer deflate(boolean deflate) {
			this.deflate = deflate;
			return this;
		}

		String encode() {
			byte[] bytes = (this.deflate) ? Saml2Utils.samlDeflate(this.decoded)
					: this.decoded.getBytes(StandardCharsets.UTF_8);
			return Saml2Utils.samlEncode(bytes);
		}

	}

	static final class DecodingConfigurer {

		private static final Base64Checker BASE_64_CHECKER = new Base64Checker();

		private final String encoded;

		private boolean inflate;

		private boolean requireBase64;

		private DecodingConfigurer(String encoded) {
			this.encoded = encoded;
		}

		DecodingConfigurer inflate(boolean inflate) {
			this.inflate = inflate;
			return this;
		}

		DecodingConfigurer requireBase64(boolean requireBase64) {
			this.requireBase64 = requireBase64;
			return this;
		}

		String decode() {
			if (this.requireBase64) {
				BASE_64_CHECKER.checkAcceptable(this.encoded);
			}
			byte[] bytes = Saml2Utils.samlDecode(this.encoded);
			return (this.inflate) ? Saml2Utils.samlInflate(bytes) : new String(bytes, StandardCharsets.UTF_8);
		}

		static class Base64Checker {

			private static final int[] values = genValueMapping();

			Base64Checker() {

			}

			private static int[] genValueMapping() {
				byte[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
					.getBytes(StandardCharsets.ISO_8859_1);

				int[] values = new int[256];
				Arrays.fill(values, -1);
				for (int i = 0; i < alphabet.length; i++) {
					values[alphabet[i] & 0xff] = i;
				}
				return values;
			}

			boolean isAcceptable(String s) {
				int goodChars = 0;
				int lastGoodCharVal = -1;

				// count number of characters from Base64 alphabet
				for (int i = 0; i < s.length(); i++) {
					int val = values[0xff & s.charAt(i)];
					if (val != -1) {
						lastGoodCharVal = val;
						goodChars++;
					}
				}

				// in cases of an incomplete final chunk, ensure the unused bits are zero
				switch (goodChars % 4) {
					case 0:
						return true;
					case 2:
						return (lastGoodCharVal & 0b1111) == 0;
					case 3:
						return (lastGoodCharVal & 0b11) == 0;
					default:
						return false;
				}
			}

			void checkAcceptable(String ins) {
				if (!isAcceptable(ins)) {
					throw new IllegalArgumentException("Failed to decode SAMLResponse");
				}
			}

		}

	}

}
