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

package org.springframework.security.webauthn.endpoint;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.Objects;
import java.util.Set;

/**
 * JSON serialization friendly variant of {@link PublicKeyCredentialDescriptor}
 *
 * @author Yoshikazu Nojima
 */
public class WebAuthnPublicKeyCredentialDescriptor implements Serializable {

	// ~ Instance fields
	// ================================================================================================

	@JsonProperty
	private PublicKeyCredentialType type;
	@JsonProperty
	private String id;
	private Set<AuthenticatorTransport> transports;

	// ~ Constructor
	// ========================================================================================================

	@JsonCreator
	public WebAuthnPublicKeyCredentialDescriptor(
			@JsonProperty("type") PublicKeyCredentialType type,
			@JsonProperty("id") String id,
			@JsonProperty("transports") Set<AuthenticatorTransport> transports) {
		this.type = type;
		this.id = id;
		this.transports = CollectionUtil.unmodifiableSet(transports);
	}

	public WebAuthnPublicKeyCredentialDescriptor(
			PublicKeyCredentialType type,
			String id) {
		this.type = type;
		this.id = id;
	}

	public WebAuthnPublicKeyCredentialDescriptor(
			String id) {
		this.type = PublicKeyCredentialType.PUBLIC_KEY;
		this.id = id;
	}


	// ~ Methods
	// ========================================================================================================

	public PublicKeyCredentialType getType() {
		return type;
	}

	public String getId() {
		return id;
	}

	public Set<AuthenticatorTransport> getTransports() {
		return transports;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WebAuthnPublicKeyCredentialDescriptor that = (WebAuthnPublicKeyCredentialDescriptor) o;
		return type == that.type &&
				Objects.equals(id, that.id);
	}

	@Override
	public int hashCode() {
		return Objects.hash(type, id);
	}
}
