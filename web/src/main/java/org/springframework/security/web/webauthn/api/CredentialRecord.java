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

import java.time.Instant;
import java.util.Set;

/**
 * Represents a <a href="https://www.w3.org/TR/webauthn-3/#credential-record">Credential
 * Record</a> that is stored by the Relying Party
 * <a href="https://www.w3.org/TR/webauthn-3/#reg-ceremony-store-credential-record">after
 * successful registration</a>.
 *
 * @author Rob Winch
 * @since 6.4
 */
public interface CredentialRecord {

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-type">credential.type</a>
	 * @return
	 */
	PublicKeyCredentialType getCredentialType();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-id">credential.id</a>.
	 * @return
	 */
	Bytes getCredentialId();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-publickey">publicKey</a>
	 * @return
	 */
	PublicKeyCose getPublicKey();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-signcount">authData.signCount</a>
	 * @return
	 */
	long getSignatureCount();

	/**
	 * <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-uvinitialized">uvInitialized</a>
	 * is the value of the UV (user verified) flag in authData and indicates whether any
	 * credential from this public key credential source has had the UV flag set.
	 * @return
	 */
	boolean isUvInitialized();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-transports">transpots</a>
	 * is the value returned from {@code response.getTransports()}.
	 * @return
	 */
	Set<AuthenticatorTransport> getTransports();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-backupeligible">backupElgible</a>
	 * flag is the same as the BE flag in authData.
	 * @return
	 */
	boolean isBackupEligible();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-backupstate">backupState</a>
	 * flag is the same as the BS flag in authData.
	 * @return
	 */
	boolean isBackupState();

	/**
	 * A reference to the associated {@link PublicKeyCredentialUserEntity#getId()}
	 * @return
	 */
	Bytes getUserEntityUserId();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-attestationobject">attestationObject</a>
	 * is the value of the attestationObject attribute when the public key credential
	 * source was registered.
	 * @return the attestationObject
	 */
	Bytes getAttestationObject();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-attestationclientdatajson">attestationClientDataJSON</a>
	 * is the value of the attestationObject attribute when the public key credential
	 * source was registered.
	 * @return
	 */
	Bytes getAttestationClientDataJSON();

	/**
	 * A human-readable label for this {@link CredentialRecord} assigned by the user.
	 * @return a label
	 */
	String getLabel();

	/**
	 * The last time this {@link CredentialRecord} was used.
	 * @return the last time this {@link CredentialRecord} was used.
	 */
	Instant getLastUsed();

	/**
	 * When this {@link CredentialRecord} was created.
	 * @return When this {@link CredentialRecord} was created.
	 */
	Instant getCreated();

}
