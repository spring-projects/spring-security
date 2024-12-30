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

/**
 * The <a href=
 * "https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity">PublicKeyCredentialRpEntity</a>
 * dictionary is used to supply additional Relying Party attributes when creating a new
 * credential.
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class PublicKeyCredentialRpEntity {

	private final String name;

	private final String id;

	private PublicKeyCredentialRpEntity(String name, String id) {
		this.name = name;
		this.id = id;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialentity-name">name</a>
	 * property is a human-palatable name for the entity. Its function depends on what the
	 * PublicKeyCredentialEntity represents for the Relying Party, intended only for
	 * display.
	 * @return the name
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrpentity-id">id</a>
	 * property is a unique identifier for the Relying Party entity, which sets the
	 * <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a>.
	 * @return the relying party id
	 */
	public String getId() {
		return this.id;
	}

	/**
	 * Creates a new {@link PublicKeyCredentialRpEntityBuilder}
	 * @return a new {@link PublicKeyCredentialRpEntityBuilder}
	 */
	public static PublicKeyCredentialRpEntityBuilder builder() {
		return new PublicKeyCredentialRpEntityBuilder();
	}

	/**
	 * Used to create a {@link PublicKeyCredentialRpEntity}.
	 *
	 * @author Rob Winch
	 * @since 6.4
	 */
	public static final class PublicKeyCredentialRpEntityBuilder {

		private String name;

		private String id;

		private PublicKeyCredentialRpEntityBuilder() {
		}

		/**
		 * Sets the {@link #getName()} property.
		 * @param name the name property
		 * @return the {@link PublicKeyCredentialRpEntityBuilder}
		 */
		public PublicKeyCredentialRpEntityBuilder name(String name) {
			this.name = name;
			return this;
		}

		/**
		 * Sets the {@link #getId()} property.
		 * @param id the id
		 * @return the {@link PublicKeyCredentialRpEntityBuilder}
		 */
		public PublicKeyCredentialRpEntityBuilder id(String id) {
			this.id = id;
			return this;
		}

		/**
		 * Creates a new {@link PublicKeyCredentialRpEntity}.
		 * @return a new {@link PublicKeyCredentialRpEntity}.
		 */
		public PublicKeyCredentialRpEntity build() {
			return new PublicKeyCredentialRpEntity(this.name, this.id);
		}

	}

}
