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

package org.springframework.security.webauthn.challenge;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.util.Assert;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;

public class WebAuthnChallengeImpl implements WebAuthnChallenge {
	private final byte[] value;

	/**
	 * Creates a new instance
	 *
	 * @param value the value of the challenge
	 */
	public WebAuthnChallengeImpl(byte[] value) {
		Assert.notNull(value, "value cannot be null");
		this.value = ArrayUtil.clone(value);
	}

	public WebAuthnChallengeImpl(String base64urlString) {
		Assert.notNull(base64urlString, "base64urlString cannot be null");
		this.value = Base64UrlUtil.decode(base64urlString);
	}

	public WebAuthnChallengeImpl() {
		UUID uuid = UUID.randomUUID();
		long hi = uuid.getMostSignificantBits();
		long lo = uuid.getLeastSignificantBits();
		this.value = ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
	}

	@JsonCreator
	public WebAuthnChallengeImpl create(String base64url) {
		return new WebAuthnChallengeImpl(Base64UrlUtil.decode(base64url));
	}

	@JsonValue
	public String toBase64UrlString() {
		return Base64UrlUtil.encodeToString(getValue());
	}

	@Override
	public byte[] getValue() {
		return ArrayUtil.clone(value);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WebAuthnChallengeImpl that = (WebAuthnChallengeImpl) o;
		return Arrays.equals(value, that.value);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(value);
	}
}
