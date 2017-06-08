/*
 * Copyright 2017-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.abac.service.jdbc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.abac.model.Policy;
import org.springframework.security.abac.service.AbstractPolicyService;
import org.springframework.util.Assert;

import javax.sql.DataSource;
import java.util.List;

/**
 * Default implementation to load ABAC policies from database
 *
 * @author Renato Soppelsa
 * @since 5.0
 */
public class JdbcPolicyServiceImpl extends AbstractPolicyService {

	private static final Log logger = LogFactory.getLog(JdbcPolicyServiceImpl.class);

	private static final String QUERY_SELECT_ABAC = "select id, name, description, type, applicable, condition from ";

	private static String DEFAULT_ABAC_TABLE_NAME = "abac";

	private String tableName;

	private JdbcTemplate jdbcTemplate;

	public void loadPolicies() {
		List<Policy> policies = jdbcTemplate.query(QUERY_SELECT_ABAC + tableName, new PolicyRowMapper());
		this.setPolicies(policies);
	}

	public JdbcPolicyServiceImpl(DataSource dataSource) {
		this(dataSource, DEFAULT_ABAC_TABLE_NAME);
	}

	public JdbcPolicyServiceImpl(DataSource dataSource, String tableName) {
		Assert.notNull(dataSource, "DataSource required");
		Assert.notNull(dataSource, "Table name for abac required");
		this.jdbcTemplate = new JdbcTemplate(dataSource);
		this.tableName = tableName;
		loadPolicies();
	}

	@Override
	public void reloadPolicies() {
		loadPolicies();
	}


}
