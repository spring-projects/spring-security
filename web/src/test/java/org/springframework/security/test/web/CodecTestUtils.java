/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.test.web;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.util.DigestUtils;

public final class CodecTestUtils {

	private CodecTestUtils() {
	}

	public static String encodeBase64(String unencoded) {
		return Base64.getEncoder().encodeToString(unencoded.getBytes());
	}

	public static String encodeBase64(byte[] unencoded) {
		return Base64.getEncoder().encodeToString(unencoded);
	}

	public static String decodeBase64(String encoded) {
		return new String(Base64.getDecoder().decode(encoded));
	}

	public static boolean isBase64(byte[] arrayOctet) {
		try {
			Base64.getMimeDecoder().decode(arrayOctet);
			return true;

		}
		catch (Exception ex) {
			return false;
		}
	}

	public static String md5Hex(String data) {
		return DigestUtils.md5DigestAsHex(data.getBytes());
	}

	public static String algorithmHex(String algorithmName, String data) {
		try {
			MessageDigest digest = MessageDigest.getInstance(algorithmName);
			return new String(Hex.encode(digest.digest(data.getBytes())));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("No " + algorithmName + " algorithm available!");
		}
	}

}
