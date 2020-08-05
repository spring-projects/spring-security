/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 * A Datasource bean which starts an in-memory HSQL database with the supplied name and
 * shuts down the database when the application context it is defined in is closed.
 *
 * @author Luke Taylor
 */
public class TestDataSource extends DriverManagerDataSource implements DisposableBean {

	String name;

	public TestDataSource(String databaseName) {
		name = databaseName;
		System.out.println("Creating database: " + name);
		setDriverClassName("org.hsqldb.jdbcDriver");
		setUrl("jdbc:hsqldb:mem:" + databaseName);
		setUsername("sa");
		setPassword("");
	}

	public void destroy() {
		System.out.println("Shutting down database: " + name);
		new JdbcTemplate(this).execute("SHUTDOWN");
	}

}
