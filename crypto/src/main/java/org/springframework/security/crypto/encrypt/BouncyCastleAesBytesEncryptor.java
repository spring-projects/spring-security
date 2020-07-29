/*
 * Copyright 2011-2016 the original author or authors.
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

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

/**
 * Base class for AES-256 encryption using Bouncy Castle.
 *
 * @author William Tran
 *
 */
abstract class BouncyCastleAesBytesEncryptor implements BytesEncryptor {

	final KeyParameter secretKey;

	final BytesKeyGenerator ivGenerator;

	BouncyCastleAesBytesEncryptor(String password, CharSequence salt) {
		this(password, salt, KeyGenerators.secureRandom(16));
	}

	BouncyCastleAesBytesEncryptor(String password, CharSequence salt, BytesKeyGenerator ivGenerator) {
		if (ivGenerator.getKeyLength() != 16) {
			throw new IllegalArgumentException("ivGenerator key length != block size 16");
		}
		this.ivGenerator = ivGenerator;
		PBEParametersGenerator keyGenerator = new PKCS5S2ParametersGenerator();
		byte[] pkcs12PasswordBytes = PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray());
		keyGenerator.init(pkcs12PasswordBytes, Hex.decode(salt), 1024);
		this.secretKey = (KeyParameter) keyGenerator.generateDerivedParameters(256);
	}

}
