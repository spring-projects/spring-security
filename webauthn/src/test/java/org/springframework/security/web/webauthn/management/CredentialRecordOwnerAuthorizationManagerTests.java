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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestBytes;
import org.springframework.security.web.webauthn.api.TestCredentialRecords;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;

/**
 * Tests for {@link CredentialRecordOwnerAuthorizationManager}.
 *
 * @author Rob Winch
 * @since 6.5.10
 */
@ExtendWith(MockitoExtension.class)
class CredentialRecordOwnerAuthorizationManagerTests {

	@Mock
	private UserCredentialRepository userCredentials;

	@Mock
	private PublicKeyCredentialUserEntityRepository userEntities;

	@Test
	void constructorWhenNullUserCredentialsThenIllegalArgument() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new CredentialRecordOwnerAuthorizationManager(null, this.userEntities));
	}

	@Test
	void constructorWhenNullUserEntitiesTonIllegalArgument() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new CredentialRecordOwnerAuthorizationManager(this.userCredentials, null));
	}

	@Test
	void checkWhenAuthenticationNullThenDenied() {
		CredentialRecordOwnerAuthorizationManager manager = new CredentialRecordOwnerAuthorizationManager(
				this.userCredentials, this.userEntities);
		Bytes credentialId = TestCredentialRecords.userCredential().build().getCredentialId();
		AuthorizationResult decision = manager.authorize(() -> null, credentialId);
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkWhenNotAuthenticatedThenDenied() {
		CredentialRecordOwnerAuthorizationManager manager = new CredentialRecordOwnerAuthorizationManager(
				this.userCredentials, this.userEntities);
		Bytes credentialId = TestCredentialRecords.userCredential().build().getCredentialId();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
		authentication.setAuthenticated(false);
		AuthorizationResult decision = manager.authorize(() -> authentication, credentialId);
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkWhenCredentialNotFoundThenDenied() {
		CredentialRecordOwnerAuthorizationManager manager = new CredentialRecordOwnerAuthorizationManager(
				this.userCredentials, this.userEntities);
		Bytes credentialId = TestCredentialRecords.userCredential().build().getCredentialId();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "USER");
		AuthorizationResult decision = manager.authorize(() -> authentication, credentialId);
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkWhenCredentialUserEntityUserIdNullThenDenied() {
		CredentialRecordOwnerAuthorizationManager manager = new CredentialRecordOwnerAuthorizationManager(
				this.userCredentials, this.userEntities);
		Bytes credentialId = TestCredentialRecords.userCredential().build().getCredentialId();
		given(this.userCredentials.findByCredentialId(credentialId))
			.willReturn(TestCredentialRecords.userCredential().userEntityUserId(null).build());
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "USER");
		AuthorizationResult decision = manager.authorize(() -> authentication, credentialId);
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkWhenUserEntityNotFoundThenDenied() {
		CredentialRecordOwnerAuthorizationManager manager = new CredentialRecordOwnerAuthorizationManager(
				this.userCredentials, this.userEntities);
		Bytes credentialId = TestCredentialRecords.userCredential().build().getCredentialId();
		given(this.userCredentials.findByCredentialId(credentialId))
			.willReturn(TestCredentialRecords.userCredential().build());
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "USER");
		AuthorizationResult decision = manager.authorize(() -> authentication, credentialId);
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkWhenCredentialBelongsToUserThenGranted() {
		CredentialRecordOwnerAuthorizationManager manager = new CredentialRecordOwnerAuthorizationManager(
				this.userCredentials, this.userEntities);
		Bytes credentialId = TestCredentialRecords.userCredential().build().getCredentialId();
		Bytes userId = TestCredentialRecords.userCredential().build().getUserEntityUserId();
		given(this.userCredentials.findByCredentialId(credentialId))
			.willReturn(TestCredentialRecords.userCredential().build());
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.name("user")
			.id(userId)
			.displayName("User")
			.build();
		given(this.userEntities.findByUsername("user")).willReturn(userEntity);
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "USER");
		AuthorizationResult decision = manager.authorize(() -> authentication, credentialId);
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkWhenCredentialBelongsToDifferentUserThenDenied() {
		CredentialRecordOwnerAuthorizationManager manager = new CredentialRecordOwnerAuthorizationManager(
				this.userCredentials, this.userEntities);
		Bytes credentialId = TestCredentialRecords.userCredential().build().getCredentialId();
		given(this.userCredentials.findByCredentialId(credentialId))
			.willReturn(TestCredentialRecords.userCredential().build());
		PublicKeyCredentialUserEntity otherUserEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.name("user")
			.id(TestBytes.get())
			.displayName("User")
			.build();
		given(this.userEntities.findByUsername("user")).willReturn(otherUserEntity);
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "USER");
		AuthorizationResult decision = manager.authorize(() -> authentication, credentialId);
		assertThat(decision.isGranted()).isFalse();
	}

}
