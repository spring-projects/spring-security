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

package org.springframework.security.web.webauthn.api;

import java.util.Arrays;
import java.util.Base64;

/**
 * An immutable {@link PublicKeyCose}
 *
 * @author Rob Winch
 * @since 6.4
 */
public class ImmutablePublicKeyCose implements PublicKeyCose {

	private final byte[] bytes;

	/**
	 * Creates a new instance.
	 * @param bytes the raw bytes of the public key.
	 */
	public ImmutablePublicKeyCose(byte[] bytes) {
		this.bytes = Arrays.copyOf(bytes, bytes.length);
	}

	@Override
	public byte[] getBytes() {
		return Arrays.copyOf(this.bytes, this.bytes.length);
	}

	/**
	 * Creates a new instance form a Base64 URL encoded String
	 * @param base64EncodedString the base64EncodedString encoded String
	 * @return
	 */
	public static ImmutablePublicKeyCose fromBase64(String base64EncodedString) {
		byte[] decode = Base64.getUrlDecoder().decode(base64EncodedString);
		return new ImmutablePublicKeyCose(decode);
	}

}
