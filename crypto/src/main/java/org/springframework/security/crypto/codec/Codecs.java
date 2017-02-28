/*
 * Copyright 2011-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.codec;

/**
 * Quick access facility to some {@link Codec} implementations.
 *
 * @author Guillaume Wallet
 * @since 4.2.2
 */
public final class Codecs {
	private static Codec BASE64 = new Codec() {
		@Override
		public String encode(byte[] source) {
			return Utf8.decode(Base64.encode(source));
		}

		@Override
		public byte[] decode(String source) {
			return Base64.decode(Utf8.encode(source));
		}
	};

	public static Codec base64() {
		return BASE64;
	}

	private static Codec HEXADECIMAL = new Codec() {
		@Override
		public String encode(byte[] source) {
			return new String(Hex.encode(source));
		}

		@Override
		public byte[] decode(String source) {
			return Hex.decode(source);
		}
	};

	public static Codec hexadecimal() {
		return HEXADECIMAL;
	}
}
