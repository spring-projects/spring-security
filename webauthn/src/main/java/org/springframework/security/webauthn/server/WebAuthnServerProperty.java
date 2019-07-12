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

package org.springframework.security.webauthn.server;

import com.webauthn4j.util.ArrayUtil;
import org.springframework.security.webauthn.challenge.WebAuthnChallenge;

import java.util.Arrays;
import java.util.Objects;

public class WebAuthnServerProperty {
	// ~ Instance fields
	// ================================================================================================

	private final WebAuthnOrigin origin;
	private final String rpId;
	private final WebAuthnChallenge challenge;
	private final byte[] tokenBindingId;

	// ~ Constructor
	// ========================================================================================================

	public WebAuthnServerProperty(WebAuthnOrigin origin, String rpId, WebAuthnChallenge challenge, byte[] tokenBindingId) {
		this.origin = origin;
		this.rpId = rpId;
		this.challenge = challenge;
		this.tokenBindingId = ArrayUtil.clone(tokenBindingId);
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * Returns the {@link WebAuthnOrigin}
	 *
	 * @return the {@link WebAuthnOrigin}
	 */
	public WebAuthnOrigin getOrigin() {
		return origin;
	}

	/**
	 * Returns the rpId
	 *
	 * @return the rpId
	 */
	public String getRpId() {
		return rpId;
	}

	/**
	 * Returns the {@link WebAuthnChallenge}
	 *
	 * @return the {@link WebAuthnChallenge}
	 */
	public WebAuthnChallenge getChallenge() {
		return challenge;
	}

	/**
	 * Returns the tokenBindingId
	 *
	 * @return the tokenBindingId
	 */
	public byte[] getTokenBindingId() {
		return ArrayUtil.clone(tokenBindingId);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WebAuthnServerProperty that = (WebAuthnServerProperty) o;
		return Objects.equals(origin, that.origin) &&
				Objects.equals(rpId, that.rpId) &&
				Objects.equals(challenge, that.challenge) &&
				Arrays.equals(tokenBindingId, that.tokenBindingId);
	}

	@Override
	public int hashCode() {

		int result = Objects.hash(origin, rpId, challenge);
		result = 31 * result + Arrays.hashCode(tokenBindingId);
		return result;
	}

}
