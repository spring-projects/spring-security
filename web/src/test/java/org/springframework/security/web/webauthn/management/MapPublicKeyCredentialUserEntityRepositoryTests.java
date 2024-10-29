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

import org.junit.jupiter.api.Test;

import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link MapPublicKeyCredentialUserEntityRepository}.
 *
 * @author Rob Winch
 * @since 6.4
 */
class MapPublicKeyCredentialUserEntityRepositoryTests {

	private MapPublicKeyCredentialUserEntityRepository userEntities = new MapPublicKeyCredentialUserEntityRepository();

	private String username = "username";

	private PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity()
		.name(this.username)
		.build();

	@Test
	void findByIdWhenExistsThenFound() {
		this.userEntities.save(this.userEntity);
		PublicKeyCredentialUserEntity findById = this.userEntities.findById(this.userEntity.getId());
		assertThat(findById).isEqualTo(this.userEntity);
	}

	@Test
	void findByIdWhenDoesNotExistThenNull() {
		PublicKeyCredentialUserEntity findById = this.userEntities.findById(this.userEntity.getId());
		assertThat(findById).isNull();
	}

	@Test
	void findByUsernameWhenExistsThenFound() {
		this.userEntities.save(this.userEntity);
		PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(this.username);
		assertThat(foundUserEntity).isEqualTo(this.userEntity);
	}

	@Test
	void findByUsernameReturnsNullWhenUsernameDoesNotExist() {
		PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(this.username);
		assertThat(foundUserEntity).isNull();
	}

	@Test
	void saveWhenNonNullThenSuccess() {
		this.userEntities.save(this.userEntity);
		PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(this.username);
		assertThat(foundUserEntity).isEqualTo(this.userEntity);
	}

	@Test
	void saveWhenUpdateThenUpdated() {
		PublicKeyCredentialUserEntity newUserEntity = TestPublicKeyCredentialUserEntity.userEntity()
			.name(this.userEntity.getName())
			.displayName("Updated")
			.build();
		this.userEntities.save(this.userEntity);
		this.userEntities.save(newUserEntity);
		PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(this.username);
		assertThat(foundUserEntity).isEqualTo(newUserEntity);
	}

	@Test
	void deleteWhenExistsThenRemovesExistingEntry() {
		this.userEntities.save(this.userEntity);
		this.userEntities.delete(this.userEntity.getId());
		assertThat(this.userEntities.findByUsername(this.username)).isNull();
		assertThat(this.userEntities.findById(this.userEntity.getId())).isNull();
	}

	@Test
	void deleteWhenNullAndDoesNotExistThenNoException() {
		assertThatNoException().isThrownBy(() -> this.userEntities.delete(this.userEntity.getId()));
	}

}
