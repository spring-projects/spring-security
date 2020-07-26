/*
 * Copyright 2002-2012 the original author or authors.
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

package org.springframework.security.web.authentication.rememberme;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Luke Taylor
 */
@RunWith(MockitoJUnitRunner.class)
public class JdbcTokenRepositoryImplTests {

	@Mock
	private Log logger;

	private static SingleConnectionDataSource dataSource;

	private JdbcTokenRepositoryImpl repo;

	private JdbcTemplate template;

	@BeforeClass
	public static void createDataSource() {
		dataSource = new SingleConnectionDataSource("jdbc:hsqldb:mem:tokenrepotest", "sa", "", true);
		dataSource.setDriverClassName("org.hsqldb.jdbc.JDBCDriver");
	}

	@AfterClass
	public static void clearDataSource() {
		dataSource.destroy();
		dataSource = null;
	}

	@Before
	public void populateDatabase() {
		this.repo = new JdbcTokenRepositoryImpl();
		ReflectionTestUtils.setField(this.repo, "logger", this.logger);
		this.repo.setDataSource(dataSource);
		this.repo.initDao();
		this.template = this.repo.getJdbcTemplate();
		this.template.execute("create table persistent_logins (username varchar(100) not null, "
				+ "series varchar(100) not null, token varchar(500) not null, last_used timestamp not null)");
	}

	@After
	public void clearData() {
		this.template.execute("drop table persistent_logins");
	}

	@Test
	public void createNewTokenInsertsCorrectData() {
		Timestamp currentDate = new Timestamp(Calendar.getInstance().getTimeInMillis());
		PersistentRememberMeToken token = new PersistentRememberMeToken("joeuser", "joesseries", "atoken", currentDate);
		this.repo.createNewToken(token);

		Map<String, Object> results = this.template.queryForMap("select * from persistent_logins");

		assertThat(results.get("last_used")).isEqualTo(currentDate);
		assertThat(results.get("username")).isEqualTo("joeuser");
		assertThat(results.get("series")).isEqualTo("joesseries");
		assertThat(results.get("token")).isEqualTo("atoken");
	}

	@Test
	public void retrievingTokenReturnsCorrectData() {

		this.template.execute("insert into persistent_logins (series, username, token, last_used) values "
				+ "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')");
		PersistentRememberMeToken token = this.repo.getTokenForSeries("joesseries");

		assertThat(token.getUsername()).isEqualTo("joeuser");
		assertThat(token.getSeries()).isEqualTo("joesseries");
		assertThat(token.getTokenValue()).isEqualTo("atoken");
		assertThat(token.getDate()).isEqualTo(Timestamp.valueOf("2007-10-09 18:19:25.000000000"));
	}

	@Test
	public void retrievingTokenWithDuplicateSeriesReturnsNull() {
		this.template.execute("insert into persistent_logins (series, username, token, last_used) values "
				+ "('joesseries', 'joeuser', 'atoken2', '2007-10-19 18:19:25.000000000')");
		this.template.execute("insert into persistent_logins (series, username, token, last_used) values "
				+ "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')");

		// List results =
		// template.queryForList("select * from persistent_logins where series =
		// 'joesseries'");

		assertThat(this.repo.getTokenForSeries("joesseries")).isNull();
	}

	// SEC-1964
	@Test
	public void retrievingTokenWithNoSeriesReturnsNull() {
		when(this.logger.isDebugEnabled()).thenReturn(true);

		assertThat(this.repo.getTokenForSeries("missingSeries")).isNull();

		verify(this.logger).isDebugEnabled();
		verify(this.logger).debug(eq("Querying token for series 'missingSeries' returned no results."),
				any(EmptyResultDataAccessException.class));
		verifyNoMoreInteractions(this.logger);
	}

	@Test
	public void removingUserTokensDeletesData() {
		this.template.execute("insert into persistent_logins (series, username, token, last_used) values "
				+ "('joesseries2', 'joeuser', 'atoken2', '2007-10-19 18:19:25.000000000')");
		this.template.execute("insert into persistent_logins (series, username, token, last_used) values "
				+ "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')");

		// List results =
		// template.queryForList("select * from persistent_logins where series =
		// 'joesseries'");

		this.repo.removeUserTokens("joeuser");

		List<Map<String, Object>> results = this.template
				.queryForList("select * from persistent_logins where username = 'joeuser'");

		assertThat(results).isEmpty();
	}

	@Test
	public void updatingTokenModifiesTokenValueAndLastUsed() {
		Timestamp ts = new Timestamp(System.currentTimeMillis() - 1);
		this.template.execute("insert into persistent_logins (series, username, token, last_used) values "
				+ "('joesseries', 'joeuser', 'atoken', '" + ts.toString() + "')");
		this.repo.updateToken("joesseries", "newtoken", new Date());

		Map<String, Object> results = this.template
				.queryForMap("select * from persistent_logins where series = 'joesseries'");

		assertThat(results.get("username")).isEqualTo("joeuser");
		assertThat(results.get("series")).isEqualTo("joesseries");
		assertThat(results.get("token")).isEqualTo("newtoken");
		Date lastUsed = (Date) results.get("last_used");
		assertThat(lastUsed.getTime() > ts.getTime()).isTrue();
	}

	@Test
	public void createTableOnStartupCreatesCorrectTable() {
		this.template.execute("drop table persistent_logins");
		this.repo = new JdbcTokenRepositoryImpl();
		this.repo.setDataSource(dataSource);
		this.repo.setCreateTableOnStartup(true);
		this.repo.initDao();

		this.template.queryForList("select username,series,token,last_used from persistent_logins");
	}

	// SEC-2879
	@Test
	public void updateUsesLastUsed() {
		JdbcTemplate template = mock(JdbcTemplate.class);
		Date lastUsed = new Date(1424841314059L);
		JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
		repository.setJdbcTemplate(template);

		repository.updateToken("series", "token", lastUsed);

		verify(template).update(anyString(), anyString(), eq(lastUsed), anyString());
	}

}
