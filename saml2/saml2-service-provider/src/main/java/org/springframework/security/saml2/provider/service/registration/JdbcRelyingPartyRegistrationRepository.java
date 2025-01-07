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

package org.springframework.security.saml2.provider.service.registration;

import org.springframework.jdbc.core.*;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.ByteArrayInputStream;
import java.sql.ResultSet;
import java.sql.Types;
import java.util.*;
import java.util.stream.Collectors;

/**
 * A JDBC implementation of {@link RelyingPartyRegistrationRepository}. Also
 * implements {@link Iterable} to simplify the default login page.
 *
 * @author َAmir Elgayed
 * @since 6.5
 */

// TODO https://github.com/spring-projects/spring-security/issues/16012
public class JdbcRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {
	// TODO add logging
	private final JdbcOperations jdbcOperations;

	// TODO ticket specifies that data is saved in the DB as XML
	private static final String TABLE_NAME = "relying_party_registration";

	private static final String[] COLUMN_NAMES = {"id", "metadata"};

	private static final String JOINT_COLUMN_NAMES = String.join(", ", COLUMN_NAMES);

	private static final String FILTER = "id = ?";

	// @formatter:off
	private static final String SAVE_RELYING_PARTY_REGISTRATION_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + JOINT_COLUMN_NAMES + ")"
			+ " VALUES ("
			+ Arrays.stream(COLUMN_NAMES).map(columnName -> "?").collect(Collectors.joining(", "))
			+")";

	private static final String SELECT_RELYING_PARTY_REGISTRATION_SQL = "SELECT "
			+ JOINT_COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + FILTER;
	// @formatter:on

	private static final String DELETE_RELYING_PARTY_REGISTRATION_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + FILTER;

	/**
	 * Constructs a {@code JdbcRelyingPartyRegistrationRepository} using the provide parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcRelyingPartyRegistrationRepository(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
	}

	// TODO to be removed
	private static Map<String, RelyingPartyRegistration> createMappingToIdentityProvider(
			Collection<RelyingPartyRegistration> rps) {
		LinkedHashMap<String, RelyingPartyRegistration> result = new LinkedHashMap<>();
		for (RelyingPartyRegistration rp : rps) {
			Assert.notNull(rp, "relying party collection cannot contain null values");
			String key = rp.getRegistrationId();
			Assert.notNull(key, "relying party identifier cannot be null");
			Assert.isNull(result.get(key), () -> "relying party duplicate identifier '" + key + "' detected.");
			result.put(key, rp);
		}
		return Collections.unmodifiableMap(result);
	}

	// TODO to be removed
	private static Map<String, List<RelyingPartyRegistration>> createMappingByAssertingPartyEntityId(
			Collection<RelyingPartyRegistration> rps) {
		MultiValueMap<String, RelyingPartyRegistration> result = new LinkedMultiValueMap<>();
		for (RelyingPartyRegistration rp : rps) {
			result.add(rp.getAssertingPartyMetadata().getEntityId(), rp);
		}
		return Collections.unmodifiableMap(result);
	}

	private String fetchRelyingRegistryMetadata(String id){
		SqlParameterValue[] parameters = { new SqlParameterValue(Types.VARCHAR, id) };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		return this.jdbcOperations.query(
				SELECT_RELYING_PARTY_REGISTRATION_SQL,
				pss,
				(ResultSet rs) -> rs.getString("metadata")
		);
	}

	// TODO test contract: return null if no match is found
	@Override
	public RelyingPartyRegistration findByRegistrationId(String id) {
		String metadata = fetchRelyingRegistryMetadata(id);
		return RelyingPartyRegistrations.fromMetadata(new ByteArrayInputStream(metadata.getBytes())).build();
	}
}
