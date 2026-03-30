/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.webauthn.management;

import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that grants access when the {@link CredentialRecord}
 * identified by the provided credential id is owned by the currently authenticated user.
 *
 * <p>
 * Per the <a href="https://www.w3.org/TR/webauthn-3/#credential-id">WebAuthn
 * specification</a>, a credential id must contain at least 16 bytes with at least 100
 * bits of entropy, making it practically unguessable. The specification also advises that
 * credential ids should be kept private, as exposing them can leak personally identifying
 * information (see
 * <a href="https://www.w3.org/TR/webauthn-3/#sctn-credential-id-privacy-leak">§ 14.6.3
 * Privacy leak via credential IDs</a>). This {@link AuthorizationManager} is therefore
 * intended as defense in depth: even if a credential id were somehow exposed, an
 * unauthorized user could not delete another user's credential.
 *
 * @author Rob Winch
 * @since 6.5.10
 */
public final class CredentialRecordOwnerAuthorizationManager implements AuthorizationManager<Bytes> {

	private final AuthenticatedAuthorizationManager<Bytes> authenticatedAuthorizationManager = AuthenticatedAuthorizationManager
		.authenticated();

	private final UserCredentialRepository userCredentials;

	private final PublicKeyCredentialUserEntityRepository userEntities;

	/**
	 * Creates a new instance.
	 * @param userCredentials the {@link UserCredentialRepository} to use
	 * @param userEntities the {@link PublicKeyCredentialUserEntityRepository} to use
	 */
	public CredentialRecordOwnerAuthorizationManager(UserCredentialRepository userCredentials,
			PublicKeyCredentialUserEntityRepository userEntities) {
		Assert.notNull(userCredentials, "userCredentials cannot be null");
		Assert.notNull(userEntities, "userEntities cannot be null");
		this.userCredentials = userCredentials;
		this.userEntities = userEntities;
	}

	@Override
	public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
			Bytes credentialId) {
		AuthorizationResult decision = this.authenticatedAuthorizationManager.authorize(authentication, credentialId);
		if (!decision.isGranted()) {
			return decision;
		}
		Authentication auth = authentication.get();
		CredentialRecord credential = this.userCredentials.findByCredentialId(credentialId);
		if (credential == null) {
			return new AuthorizationDecision(false);
		}
		if (credential.getUserEntityUserId() == null) {
			return new AuthorizationDecision(false);
		}
		PublicKeyCredentialUserEntity userEntity = this.userEntities.findByUsername(auth.getName());
		if (userEntity == null) {
			return new AuthorizationDecision(false);
		}
		return new AuthorizationDecision(credential.getUserEntityUserId().equals(userEntity.getId()));
	}

}
