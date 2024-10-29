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
 * An immutable {@link CredentialRecord}.
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class ImmutableCredentialRecord implements CredentialRecord {

	private final PublicKeyCredentialType credentialType;

	private final Bytes credentialId;

	private final Bytes userEntityUserId;

	private final PublicKeyCose publicKey;

	private final long signatureCount;

	private final boolean uvInitialized;

	private final Set<AuthenticatorTransport> transports;

	private final boolean backupEligible;

	private final boolean backupState;

	private final Bytes attestationObject;

	private final Bytes attestationClientDataJSON;

	private final Instant created;

	private final Instant lastUsed;

	private final String label;

	private ImmutableCredentialRecord(PublicKeyCredentialType credentialType, Bytes credentialId,
			Bytes userEntityUserId, PublicKeyCose publicKey, long signatureCount, boolean uvInitialized,
			Set<AuthenticatorTransport> transports, boolean backupEligible, boolean backupState,
			Bytes attestationObject, Bytes attestationClientDataJSON, Instant created, Instant lastUsed, String label) {
		this.credentialType = credentialType;
		this.credentialId = credentialId;
		this.userEntityUserId = userEntityUserId;
		this.publicKey = publicKey;
		this.signatureCount = signatureCount;
		this.uvInitialized = uvInitialized;
		this.transports = transports;
		this.backupEligible = backupEligible;
		this.backupState = backupState;
		this.attestationObject = attestationObject;
		this.attestationClientDataJSON = attestationClientDataJSON;
		this.created = created;
		this.lastUsed = lastUsed;
		this.label = label;
	}

	@Override
	public PublicKeyCredentialType getCredentialType() {
		return this.credentialType;
	}

	@Override
	public Bytes getCredentialId() {
		return this.credentialId;
	}

	@Override
	public Bytes getUserEntityUserId() {
		return this.userEntityUserId;
	}

	@Override
	public PublicKeyCose getPublicKey() {
		return this.publicKey;
	}

	@Override
	public long getSignatureCount() {
		return this.signatureCount;
	}

	@Override
	public boolean isUvInitialized() {
		return this.uvInitialized;
	}

	@Override
	public Set<AuthenticatorTransport> getTransports() {
		return this.transports;
	}

	@Override
	public boolean isBackupEligible() {
		return this.backupEligible;
	}

	@Override
	public boolean isBackupState() {
		return this.backupState;
	}

	@Override
	public Bytes getAttestationObject() {
		return this.attestationObject;
	}

	@Override
	public Bytes getAttestationClientDataJSON() {
		return this.attestationClientDataJSON;
	}

	@Override
	public Instant getCreated() {
		return this.created;
	}

	@Override
	public Instant getLastUsed() {
		return this.lastUsed;
	}

	@Override
	public String getLabel() {
		return this.label;
	}

	public static ImmutableCredentialRecordBuilder builder() {
		return new ImmutableCredentialRecordBuilder();
	}

	public static ImmutableCredentialRecordBuilder fromCredentialRecord(CredentialRecord credentialRecord) {
		return new ImmutableCredentialRecordBuilder(credentialRecord);
	}

	public static final class ImmutableCredentialRecordBuilder {

		private PublicKeyCredentialType credentialType;

		private Bytes credentialId;

		private Bytes userEntityUserId;

		private PublicKeyCose publicKey;

		private long signatureCount;

		private boolean uvInitialized;

		private Set<AuthenticatorTransport> transports;

		private boolean backupEligible;

		private boolean backupState;

		private Bytes attestationObject;

		private Bytes attestationClientDataJSON;

		private Instant created = Instant.now();

		private Instant lastUsed = this.created;

		private String label;

		private ImmutableCredentialRecordBuilder() {
		}

		private ImmutableCredentialRecordBuilder(CredentialRecord other) {
			this.credentialType = other.getCredentialType();
			this.credentialId = other.getCredentialId();
			this.userEntityUserId = other.getUserEntityUserId();
			this.publicKey = other.getPublicKey();
			this.signatureCount = other.getSignatureCount();
			this.uvInitialized = other.isUvInitialized();
			this.transports = other.getTransports();
			this.backupEligible = other.isBackupEligible();
			this.backupState = other.isBackupState();
			this.attestationObject = other.getAttestationObject();
			this.attestationClientDataJSON = other.getAttestationClientDataJSON();
			this.created = other.getCreated();
			this.lastUsed = other.getLastUsed();
			this.label = other.getLabel();
		}

		public ImmutableCredentialRecordBuilder credentialType(PublicKeyCredentialType credentialType) {
			this.credentialType = credentialType;
			return this;
		}

		public ImmutableCredentialRecordBuilder credentialId(Bytes credentialId) {
			this.credentialId = credentialId;
			return this;
		}

		public ImmutableCredentialRecordBuilder userEntityUserId(Bytes userEntityUserId) {
			this.userEntityUserId = userEntityUserId;
			return this;
		}

		public ImmutableCredentialRecordBuilder publicKey(PublicKeyCose publicKey) {
			this.publicKey = publicKey;
			return this;
		}

		public ImmutableCredentialRecordBuilder signatureCount(long signatureCount) {
			this.signatureCount = signatureCount;
			return this;
		}

		public ImmutableCredentialRecordBuilder uvInitialized(boolean uvInitialized) {
			this.uvInitialized = uvInitialized;
			return this;
		}

		public ImmutableCredentialRecordBuilder transports(Set<AuthenticatorTransport> transports) {
			this.transports = transports;
			return this;
		}

		public ImmutableCredentialRecordBuilder backupEligible(boolean backupEligible) {
			this.backupEligible = backupEligible;
			return this;
		}

		public ImmutableCredentialRecordBuilder backupState(boolean backupState) {
			this.backupState = backupState;
			return this;
		}

		public ImmutableCredentialRecordBuilder attestationObject(Bytes attestationObject) {
			this.attestationObject = attestationObject;
			return this;
		}

		public ImmutableCredentialRecordBuilder attestationClientDataJSON(Bytes attestationClientDataJSON) {
			this.attestationClientDataJSON = attestationClientDataJSON;
			return this;
		}

		public ImmutableCredentialRecordBuilder created(Instant created) {
			this.created = created;
			return this;
		}

		public ImmutableCredentialRecordBuilder lastUsed(Instant lastUsed) {
			this.lastUsed = lastUsed;
			return this;
		}

		public ImmutableCredentialRecordBuilder label(String label) {
			this.label = label;
			return this;
		}

		public ImmutableCredentialRecord build() {
			return new ImmutableCredentialRecord(this.credentialType, this.credentialId, this.userEntityUserId,
					this.publicKey, this.signatureCount, this.uvInitialized, this.transports, this.backupEligible,
					this.backupState, this.attestationObject, this.attestationClientDataJSON, this.created,
					this.lastUsed, this.label);
		}

	}

}
