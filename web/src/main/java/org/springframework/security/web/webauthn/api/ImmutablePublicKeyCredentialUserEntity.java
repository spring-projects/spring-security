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
 * <a href=
 * "https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity">PublicKeyCredentialUserEntity</a>
 * is used to supply additional
 * <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> attributes
 * when creating a new credential.
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class ImmutablePublicKeyCredentialUserEntity implements PublicKeyCredentialUserEntity {

	/**
	 * When inherited by PublicKeyCredentialUserEntity, it is a human-palatable identifier
	 * for a user account. It is intended only for display, i.e., aiding the user in
	 * determining the difference between user accounts with similar displayNames. For
	 * example, "alexm", "alex.mueller@example.com" or "+14255551234".
	 *
	 * The Relying Party MAY let the user choose this value. The Relying Party SHOULD
	 * perform enforcement, as prescribed in Section 3.4.3 of [RFC8265] for the
	 * UsernameCasePreserved Profile of the PRECIS IdentifierClass [RFC8264], when setting
	 * name's value, or displaying the value to the user.
	 *
	 * This string MAY contain language and direction metadata. Relying Parties SHOULD
	 * consider providing this information. See 6.4.2 Language and Direction Encoding
	 * about how this metadata is encoded.
	 *
	 * Clients SHOULD perform enforcement, as prescribed in Section 3.4.3 of [RFC8265] for
	 * the UsernameCasePreserved Profile of the PRECIS IdentifierClass [RFC8264], on
	 * name's value prior to displaying the value to the user or including the value as a
	 * parameter of the authenticatorMakeCredential operation.
	 */
	private final String name;

	/**
	 * The user handle of the user account entity. A user handle is an opaque byte
	 * sequence with a maximum size of 64 bytes, and is not meant to be displayed to the
	 * user.
	 *
	 * To ensure secure operation, authentication and authorization decisions MUST be made
	 * on the basis of this id member, not the displayName nor name members. See Section
	 * 6.1 of [RFC8266].
	 *
	 * The user handle MUST NOT contain personally identifying information about the user,
	 * such as a username or e-mail address; see 14.6.1 User Handle Contents for details.
	 * The user handle MUST NOT be empty, though it MAY be null.
	 *
	 * Note: the user handle ought not be a constant value across different accounts, even
	 * for non-discoverable credentials, because some authenticators always create
	 * discoverable credentials. Thus a constant user handle would prevent a user from
	 * using such an authenticator with more than one account at the Relying Party.
	 */
	private final Bytes id;

	/**
	 * A human-palatable name for the user account, intended only for display. The Relying
	 * Party SHOULD let the user choose this, and SHOULD NOT restrict the choice more than
	 * necessary.
	 *
	 * Relying Parties SHOULD perform enforcement, as prescribed in Section 2.3 of
	 * [RFC8266] for the Nickname Profile of the PRECIS FreeformClass [RFC8264], when
	 * setting displayName's value, or displaying the value to the user.
	 *
	 * This string MAY contain language and direction metadata. Relying Parties SHOULD
	 * consider providing this information. See 6.4.2 Language and Direction Encoding
	 * about how this metadata is encoded.
	 *
	 * Clients SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for
	 * the Nickname Profile of the PRECIS FreeformClass [RFC8264], on displayName's value
	 * prior to displaying the value to the user or including the value as a parameter of
	 * the authenticatorMakeCredential operation.
	 *
	 * When clients, client platforms, or authenticators display a displayName's value,
	 * they should always use UI elements to provide a clear boundary around the displayed
	 * value, and not allow overflow into other elements [css-overflow-3].
	 *
	 * Authenticators MUST accept and store a 64-byte minimum length for a displayName
	 * member's value. Authenticators MAY truncate a displayName member's value so that it
	 * fits within 64 bytes. See 6.4.1 String Truncation about truncation and other
	 * considerations.
	 */
	private final String displayName;

	private ImmutablePublicKeyCredentialUserEntity(String name, Bytes id, String displayName) {
		this.name = name;
		this.id = id;
		this.displayName = displayName;
	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public Bytes getId() {
		return this.id;
	}

	@Override
	public String getDisplayName() {
		return this.displayName;
	}

	/**
	 * Create a new {@link PublicKeyCredentialUserEntityBuilder}
	 * @return a new {@link PublicKeyCredentialUserEntityBuilder}
	 */
	public static PublicKeyCredentialUserEntityBuilder builder() {
		return new PublicKeyCredentialUserEntityBuilder();
	}

	/**
	 * Used to build {@link PublicKeyCredentialUserEntity}.
	 *
	 * @author Rob Winch
	 * @since 6.4
	 */
	public static final class PublicKeyCredentialUserEntityBuilder {

		private String name;

		private Bytes id;

		private String displayName;

		private PublicKeyCredentialUserEntityBuilder() {
		}

		/**
		 * Sets the {@link #getName()} property.
		 * @param name the name
		 * @return the {@link PublicKeyCredentialUserEntityBuilder}
		 */
		public PublicKeyCredentialUserEntityBuilder name(String name) {
			this.name = name;
			return this;
		}

		/**
		 * Sets the {@link #getId()} property.
		 * @param id the id
		 * @return the {@link PublicKeyCredentialUserEntityBuilder}
		 */
		public PublicKeyCredentialUserEntityBuilder id(Bytes id) {
			this.id = id;
			return this;
		}

		/**
		 * Sets the {@link #getDisplayName()} property.
		 * @param displayName the display name
		 * @return the {@link PublicKeyCredentialUserEntityBuilder}
		 */
		public PublicKeyCredentialUserEntityBuilder displayName(String displayName) {
			this.displayName = displayName;
			return this;
		}

		/**
		 * Builds a new {@link PublicKeyCredentialUserEntity}
		 * @return a new {@link PublicKeyCredentialUserEntity}
		 */
		public PublicKeyCredentialUserEntity build() {
			return new ImmutablePublicKeyCredentialUserEntity(this.name, this.id, this.displayName);
		}

	}

}
