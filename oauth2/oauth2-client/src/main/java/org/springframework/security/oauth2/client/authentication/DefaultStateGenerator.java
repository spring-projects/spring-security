/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.util.Assert;

/**
 * The default implementation for generating the
 * {@link org.springframework.security.oauth2.core.endpoint.OAuth2Parameter#STATE} parameter
 * used in the <i>Authorization Request</i> and correlated in the <i>Authorization Response</i> (or <i>Error Response</i>).
 *
 * <p>
 * <b>NOTE:</b> The value of the <i>state</i> parameter is an opaque <code>String</code>
 * used by the client to prevent cross-site request forgery, as described in
 * <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-10.12">Section 10.12</a> of the specification.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class DefaultStateGenerator implements StringKeyGenerator {
	private static final int DEFAULT_BYTE_LENGTH = 32;
	private final BytesKeyGenerator keyGenerator;

	public DefaultStateGenerator() {
		this(DEFAULT_BYTE_LENGTH);
	}

	public DefaultStateGenerator(int byteLength) {
		Assert.isTrue(byteLength > 0, "byteLength must be greater than 0");
		this.keyGenerator = KeyGenerators.secureRandom(byteLength);
	}

	@Override
	public String generateKey() {
		return new String(Base64.encode(keyGenerator.generateKey()));
	}
}
