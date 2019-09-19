/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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
package org.springframework.security.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.Assert;

/**
 * Populates a database with test data for JDBC testing.
 *
 * @author Ben Alex
 */
public class DataSourcePopulator implements InitializingBean {
	// ~ Instance fields
	// ================================================================================================

	JdbcTemplate template;

	public void afterPropertiesSet() {
		Assert.notNull(template, "dataSource required");

		template.execute("CREATE TABLE USERS(USERNAME VARCHAR_IGNORECASE(50) NOT NULL PRIMARY KEY,PASSWORD VARCHAR_IGNORECASE(500) NOT NULL,ENABLED BOOLEAN NOT NULL);");
		template.execute("CREATE TABLE AUTHORITIES(USERNAME VARCHAR_IGNORECASE(50) NOT NULL,AUTHORITY VARCHAR_IGNORECASE(50) NOT NULL,CONSTRAINT FK_AUTHORITIES_USERS FOREIGN KEY(USERNAME) REFERENCES USERS(USERNAME));");
		template.execute("CREATE UNIQUE INDEX IX_AUTH_USERNAME ON AUTHORITIES(USERNAME,AUTHORITY);");

		/*
		 * Passwords encoded using MD5, NOT in Base64 format, with null as salt Encoded
		 * password for rod is "koala" Encoded password for dianne is "emu" Encoded
		 * password for scott is "wombat" Encoded password for peter is "opal" (but user
		 * is disabled) Encoded password for bill is "wombat" Encoded password for bob is
		 * "wombat" Encoded password for jane is "wombat"
		 */
		template.execute("INSERT INTO USERS VALUES('rod','{noop}koala',TRUE);");
		template.execute("INSERT INTO USERS VALUES('dianne','{MD5}65d15fe9156f9c4bbffd98085992a44e',TRUE);");
		template.execute("INSERT INTO USERS VALUES('scott','{MD5}2b58af6dddbd072ed27ffc86725d7d3a',TRUE);");
		template.execute("INSERT INTO USERS VALUES('peter','{MD5}22b5c9accc6e1ba628cedc63a72d57f8',FALSE);");
		template.execute("INSERT INTO USERS VALUES('bill','{MD5}2b58af6dddbd072ed27ffc86725d7d3a',TRUE);");
		template.execute("INSERT INTO USERS VALUES('bob','{MD5}2b58af6dddbd072ed27ffc86725d7d3a',TRUE);");
		template.execute("INSERT INTO USERS VALUES('jane','{MD5}2b58af6dddbd072ed27ffc86725d7d3a',TRUE);");
		template.execute("INSERT INTO AUTHORITIES VALUES('rod','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('rod','ROLE_SUPERVISOR');");
		template.execute("INSERT INTO AUTHORITIES VALUES('dianne','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('scott','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('peter','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('bill','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('bob','ROLE_USER');");
		template.execute("INSERT INTO AUTHORITIES VALUES('jane','ROLE_USER');");
	}

	public void setDataSource(DataSource dataSource) {
		this.template = new JdbcTemplate(dataSource);
	}
}
