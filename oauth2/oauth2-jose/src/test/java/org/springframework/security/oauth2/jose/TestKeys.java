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
package org.springframework.security.oauth2.jose;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @author Joe Grandja
 * @since 5.2
 */
public class TestKeys {
	public static final String DEFAULT_ENCODED_SECRET_KEY = "bCzY/M48bbkwBEWjmNSIEPfwApcvXOnkCxORBEbPr+4=";

	public static final SecretKey DEFAULT_SECRET_KEY =
			new SecretKeySpec(Base64.getDecoder().decode(DEFAULT_ENCODED_SECRET_KEY), "AES");

	public static SecretKey secretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		return keyGenerator.generateKey();
	}
}
