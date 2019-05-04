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

package org.springframework.security.webauthn.options;

import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Options for WebAuthn assertion generation
 */
public class AssertionOptions implements Serializable {

	// ~ Instance fields
	// ================================================================================================

	private Challenge challenge;
	private Long timeout;
	private String rpId;
	private List<PublicKeyCredentialDescriptor> allowCredentials;
	private AuthenticationExtensionsClientInputs extensions;

	// ~ Constructors
	// ===================================================================================================

	public AssertionOptions(
			Challenge challenge,
			Long timeout,
			String rpId,
			List<PublicKeyCredentialDescriptor> allowCredentials,
			AuthenticationExtensionsClientInputs extensions) {
		this.challenge = challenge;
		this.timeout = timeout;
		this.rpId = rpId;
		this.allowCredentials = CollectionUtil.unmodifiableList(allowCredentials);
		this.extensions = extensions;
	}

	// ~ Methods
	// ========================================================================================================

	public Challenge getChallenge() {
		return challenge;
	}

	public Long getTimeout() {
		return timeout;
	}

	public String getRpId() {
		return rpId;
	}

	public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
		return allowCredentials;
	}

	public AuthenticationExtensionsClientInputs getExtensions() {
		return extensions;
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		AssertionOptions that = (AssertionOptions) o;
		return Objects.equals(challenge, that.challenge) &&
				Objects.equals(timeout, that.timeout) &&
				Objects.equals(rpId, that.rpId) &&
				Objects.equals(allowCredentials, that.allowCredentials) &&
				Objects.equals(extensions, that.extensions);
	}

	@Override
	public int hashCode() {

		return Objects.hash(challenge, timeout, rpId, allowCredentials, extensions);
	}
}
