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
import com.webauthn4j.data.PublicKeyCredentialEntity;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;

import java.util.Objects;

/**
 * JSON serialization friendly variant of {@link PublicKeyCredentialUserEntity}
 *
 * @author Yoshikazu Nojima
 */
public class WebAuthnPublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {

	// ~ Instance fields
	// ================================================================================================

	private String id;
	private String displayName;

	// ~ Constructor
	// ========================================================================================================

	@JsonCreator
	public WebAuthnPublicKeyCredentialUserEntity(
			@JsonProperty("id") String id,
			@JsonProperty("name") String name,
			@JsonProperty("displayName") String displayName,
			@JsonProperty("icon") String icon) {
		super(name, icon);
		this.id = id;
		this.displayName = displayName;
	}

	// ~ Methods
	// ========================================================================================================

	public String getId() {
		return id;
	}

	public String getDisplayName() {
		return displayName;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;
		WebAuthnPublicKeyCredentialUserEntity that = (WebAuthnPublicKeyCredentialUserEntity) o;
		return Objects.equals(id, that.id) &&
				Objects.equals(displayName, that.displayName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), id, displayName);
	}
}
