/*
 * Copyright 2002-2017 the original author or authors.
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


import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

import java.io.Serializable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.core.convert.ConversionService;

/**
 * Tests for {@link AclClassIdUtils}.
 * @author paulwheeler
 */
@RunWith(MockitoJUnitRunner.class)
public class AclClassIdUtilsTest {

	private static final Long DEFAULT_IDENTIFIER = 999L;
	private static final String DEFAULT_IDENTIFIER_AS_STRING = DEFAULT_IDENTIFIER.toString();

	@Mock
	private ResultSet resultSet;
	@Mock
	private ConversionService conversionService;
	@InjectMocks
	private AclClassIdUtils aclClassIdUtils;

	@Before
	public void setUp() throws Exception {
		given(conversionService.canConvert(String.class, Long.class)).willReturn(true);
		given(conversionService.convert(DEFAULT_IDENTIFIER, Long.class)).willReturn(new Long(DEFAULT_IDENTIFIER));
		given(conversionService.convert(DEFAULT_IDENTIFIER_AS_STRING, Long.class)).willReturn(new Long(DEFAULT_IDENTIFIER));
	}

	@Test
	public void shouldReturnLongIfIdentifierIsNotStringAndNoConversionService() throws SQLException {
		// given
		AclClassIdUtils aclClassIdUtilsWithoutConversionSvc = new AclClassIdUtils();

		// when
		Serializable newIdentifier = aclClassIdUtilsWithoutConversionSvc.identifierFrom(DEFAULT_IDENTIFIER, resultSet);

		// then
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongIfIdentifierIsNotString() throws SQLException {
		// given
		Long prevIdentifier = 999L;

		// when
		Serializable newIdentifier = aclClassIdUtils.identifierFrom(prevIdentifier, resultSet);

		// then
		assertThat(newIdentifier).isEqualTo(prevIdentifier);
	}

	@Test
	public void shouldReturnLongIfClassIdTypeIsNull() throws SQLException {
		// given
		given(resultSet.getString("class_id_type")).willReturn(null);

		// when
		Serializable newIdentifier = aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, resultSet);

		// then
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongIfNoClassIdTypeColumn() throws SQLException {
		// given
		given(resultSet.getString("class_id_type")).willThrow(SQLException.class);

		// when
		Serializable newIdentifier = aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, resultSet);

		// then
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongIfTypeClassNotFound() throws SQLException {
		// given
		given(resultSet.getString("class_id_type")).willReturn("com.example.UnknownType");

		// when
		Serializable newIdentifier = aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, resultSet);

		// then
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongIfTypeClassCannotBeConverted() throws SQLException {
		// given
		given(resultSet.getString("class_id_type")).willReturn("java.lang.Long");
		given(conversionService.canConvert(String.class, Long.class)).willReturn(false);

		// when
		Serializable newIdentifier = aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, resultSet);

		// then
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnLongWhenLongClassIdType() throws SQLException {
		// given
		given(resultSet.getString("class_id_type")).willReturn("java.lang.Long");

		// when
		Serializable newIdentifier = aclClassIdUtils.identifierFrom(DEFAULT_IDENTIFIER_AS_STRING, resultSet);

		// then
		assertThat(newIdentifier).isEqualTo(DEFAULT_IDENTIFIER);
	}

	@Test
	public void shouldReturnUUIDWhenUUIDClassIdType() throws SQLException {
		// given
		UUID identifier = UUID.randomUUID();
		String identifierAsString = identifier.toString();
		given(resultSet.getString("class_id_type")).willReturn("java.util.UUID");
		given(conversionService.canConvert(String.class, UUID.class)).willReturn(true);
		given(conversionService.convert(identifierAsString, UUID.class)).willReturn(UUID.fromString(identifierAsString));

		// when
		Serializable newIdentifier = aclClassIdUtils.identifierFrom(identifier.toString(), resultSet);

		// then
		assertThat(newIdentifier).isEqualTo(identifier);
	}

}
