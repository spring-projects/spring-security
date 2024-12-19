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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JdbcPublicKeyCredentialUserEntityRepository}
 *
 * @author Max Batischev
 */
public class JdbcPublicKeyCredentialUserEntityRepositoryTests {

	private EmbeddedDatabase db;

	private JdbcPublicKeyCredentialUserEntityRepository repository;

	private static final String USER_ENTITIES_SQL_RESOURCE = "org/springframework/security/user-entities-schema.sql";

	@BeforeEach
	void setUp() {
		this.db = createDb();
		JdbcOperations jdbcOperations = new JdbcTemplate(this.db);
		this.repository = new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
	}

	@AfterEach
	void tearDown() {
		this.db.shutdown();
	}

	private static EmbeddedDatabase createDb() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript(USER_ENTITIES_SQL_RESOURCE)
				.build();
		// @formatter:on
	}

	@Test
	void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcPublicKeyCredentialUserEntityRepository(null))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	void saveWhenUserEntityIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.repository.save(null))
				.withMessage("userEntity cannot be null");
		// @formatter:on
	}

	@Test
	void findByUserEntityIdWheIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.repository.findById(null))
				.withMessage("id cannot be null");
		// @formatter:on
	}

	@Test
	void findByUserNameWheUserNameIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.repository.findByUsername(null))
				.withMessage("name cannot be null or empty");
		// @formatter:on
	}

	@Test
	void saveUserEntityWhenSaveThenReturnsSaved() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();

		this.repository.save(userEntity);

		PublicKeyCredentialUserEntity savedUserEntity = this.repository.findById(userEntity.getId());
		assertThat(savedUserEntity).isNotNull();
		assertThat(savedUserEntity.getId()).isEqualTo(userEntity.getId());
		assertThat(savedUserEntity.getDisplayName()).isEqualTo(userEntity.getDisplayName());
		assertThat(savedUserEntity.getName()).isEqualTo(userEntity.getName());
	}

	@Test
	void saveUserEntityWhenUserEntityExistsThenUpdates() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();
		this.repository.save(userEntity);

		this.repository.save(testUserEntity(userEntity.getId()));

		PublicKeyCredentialUserEntity savedUserEntity = this.repository.findById(userEntity.getId());
		assertThat(savedUserEntity).isNotNull();
		assertThat(savedUserEntity.getId()).isEqualTo(userEntity.getId());
		assertThat(savedUserEntity.getDisplayName()).isEqualTo("user2");
		assertThat(savedUserEntity.getName()).isEqualTo("user2");
	}

	@Test
	void findUserEntityByUserNameWhenUserEntityExistsThenReturnsSaved() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();
		this.repository.save(userEntity);

		PublicKeyCredentialUserEntity savedUserEntity = this.repository.findByUsername(userEntity.getName());

		assertThat(savedUserEntity).isNotNull();
	}

	@Test
	void deleteUserEntityWhenRecordExistThenSuccess() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();
		this.repository.save(userEntity);

		this.repository.delete(userEntity.getId());

		PublicKeyCredentialUserEntity savedUserEntity = this.repository.findById(userEntity.getId());
		assertThat(savedUserEntity).isNull();
	}

	@Test
	void findUserEntityByIdWhenUserEntityDoesNotExistThenReturnsNull() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();

		PublicKeyCredentialUserEntity savedUserEntity = this.repository.findById(userEntity.getId());
		assertThat(savedUserEntity).isNull();
	}

	@Test
	void findUserEntityByUserNameWhenUserEntityDoesNotExistThenReturnsEmpty() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();

		PublicKeyCredentialUserEntity savedUserEntity = this.repository.findByUsername(userEntity.getName());
		assertThat(savedUserEntity).isNull();
	}

	private PublicKeyCredentialUserEntity testUserEntity(Bytes id) {
		// @formatter:off
		return ImmutablePublicKeyCredentialUserEntity.builder()
				.name("user2")
				.id(id)
				.displayName("user2")
				.build();
		// @formatter:on
	}

}
