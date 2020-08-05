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

import javax.sql.DataSource;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Tests {@link BasicLookupStrategy} with Acl Class type id not specified.
 *
 * @author Andrei Stefan
 * @author Paul Wheeler
 */
public class BasicLookupStrategyTests extends AbstractBasicLookupStrategyTests {

	private static final BasicLookupStrategyTestsDbHelper DATABASE_HELPER = new BasicLookupStrategyTestsDbHelper();

	@BeforeClass
	public static void createDatabase() throws Exception {
		DATABASE_HELPER.createDatabase();
	}

	@AfterClass
	public static void dropDatabase() {
		DATABASE_HELPER.getDataSource().destroy();
	}

	@Override
	public JdbcTemplate getJdbcTemplate() {
		return DATABASE_HELPER.getJdbcTemplate();
	}

	@Override
	public DataSource getDataSource() {
		return DATABASE_HELPER.getDataSource();
	}

}
