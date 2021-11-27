/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.acls.jdbc;

import java.io.Serializable;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.core.convert.ConversionService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;

/**
 * Tests for {@link AclClassIdUtils}.
 *
 * @author paulwheeler
 */
@ExtendWith(MockitoExtension.class)
public class AclClassIdUtilsTests {

	private static final Long DEFAULT_IDENTIFIER = 999L;

	private static final BigInteger BIGINT_IDENTIFIER = new BigInteger("999");

	private static final String DEFAULT_IDENTIFIER_AS_STRING = DEFAULT_IDENTIFIER.toString();

	@Mock
	private ResultSet resultSet;

	@Mock
	private ConversionService conversionService;

	private AclClassIdUtils aclClassIdUtils;

	@BeforeEach
	public void setUp() {
		this.aclClassIdUtils = new AclClassIdUtils();
	}

	@Test
	public void shouldReturnLongIfIdentifierIsLong() throws SQLException {
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER, this.resultSet);
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongIfIdentifierIsBigInteger() throws SQLException {
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(BIGINT_IDENTIFIER, this.resultSet);
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongIfClassIdTypeIsNull() throws SQLException {
		given(this.resultSet.getString("class_id_type")).willReturn(null);
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, this.resultSet);
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongIfNoClassIdTypeColumn() throws SQLException {
		given(this.resultSet.getString("class_id_type")).willThrow(SQLException.class);
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, this.resultSet);
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongIfTypeClassNotFound() throws SQLException {
		given(this.resultSet.getString("class_id_type")).willReturn("com.example.UnknownType");
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, this.resultSet);
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongEvenIfCustomConversionServiceDoesNotSupportLongConversion() throws SQLException {
		given(this.resultSet.getString("class_id_type")).willReturn("java.lang.Long");
		given(this.conversionService.canConvert(String.class, Long.class)).willReturn(false);
		this.aclClassIdUtils.setConversionService(this.conversionService);
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, this.resultSet);
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongWhenLongClassIdType() throws SQLException {
		given(this.resultSet.getString("class_id_type")).willReturn("java.lang.Long");
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, this.resultSet);
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnUUIDWhenUUIDClassIdType() throws SQLException {
		UUID identifier = UUID.randomUUID();
		given(this.resultSet.getString("class_id_type")).willReturn("java.util.UUID");
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(identifier.toString(), this.resultSet);
		assertThat(newIdentifier).isEqualTo(identifier);
	}

	@Test
	public void shouldReturnStringWhenStringClassIdType() throws SQLException {
		String identifier = "MY_STRING_IDENTIFIER";
		given(this.resultSet.getString("class_id_type")).willReturn("java.lang.String");
		Serializable newIdentifier = this.aclClassIdUtils.identifierFrom(identifier, this.resultSet);
		assertThat(newIdentifier).isEqualTo(identifier);
	}

	@Test
	public void shouldNotAcceptNullConversionServiceInConstruction() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AclClassIdUtils(null));
	}

	@Test
	public void shouldNotAcceptNullConversionServiceInSetter() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.aclClassIdUtils.setConversionService(null));
	}

}
