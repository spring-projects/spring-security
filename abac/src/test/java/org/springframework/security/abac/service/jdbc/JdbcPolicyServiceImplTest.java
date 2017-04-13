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

import org.h2.jdbcx.JdbcDataSource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.init.DatabasePopulator;
import org.springframework.jdbc.datasource.init.DatabasePopulatorUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.abac.model.Policy;

import javax.sql.DataSource;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(JUnit4.class)
public class JdbcPolicyServiceImplTest {

	private DataSource ds;

	private Resource schemaScript = new ClassPathResource("schema.sql");

	private Resource dataScript = new ClassPathResource("data.sql");


	private DatabasePopulator databasePopulator() {
		final ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
		populator.addScript(schemaScript);
		populator.addScript(dataScript);
		return populator;
	}

	@Before
	public void initDb() {
		JdbcDataSource ds = new JdbcDataSource();
		ds.setUser("sa");
		ds.setURL("jdbc:h2:mem:abac;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
		ds.setPassword("");
		this.ds = ds;
		DatabasePopulatorUtils.execute(databasePopulator(), ds);
	}

	@Test
	public void loadPolicies() {
		JdbcPolicyServiceImpl policyService = new JdbcPolicyServiceImpl(ds);
		List<Policy> list = policyService.getAllPolicies();
		assertThat(list).hasSize(1);
	}

}
