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

package org.springframework.security.web.webauthn.management;

import java.util.List;

import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

/**
 * A repository for managing {@link CredentialRecord}s associated to a user.
 *
 * @author Rob Winch
 * @since 6.4
 */
public interface UserCredentialRepository {

	/**
	 * Deletes an entry by credential id
	 * @param credentialId {@link CredentialRecord#getCredentialId()}
	 */
	void delete(Bytes credentialId);

	/**
	 * Saves a {@link CredentialRecord}
	 * @param credentialRecord the {@link CredentialRecord} to save.
	 */
	void save(CredentialRecord credentialRecord);

	/**
	 * Finds an entry by credential id.
	 * @param credentialId {@link CredentialRecord#getCredentialId()}
	 * @return the {@link CredentialRecord} or null if not found.
	 */
	CredentialRecord findByCredentialId(Bytes credentialId);

	/**
	 * Finds all {@link CredentialRecord} instances for a specific user.
	 * @param userId the {@link PublicKeyCredentialUserEntity#getId()} to search for a
	 * user.
	 * @return all {@link CredentialRecord} instances for a specific user or empty if no
	 * results found. Never null.
	 * @see PublicKeyCredentialUserEntityRepository
	 */
	List<CredentialRecord> findByUserId(Bytes userId);

}
