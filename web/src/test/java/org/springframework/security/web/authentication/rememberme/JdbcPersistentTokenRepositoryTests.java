/*
 * Copyright 2004-present the original author or authors.
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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.then;

/**
 * @author Andrey Litvitski
 */
@ExtendWith(MockitoExtension.class)
public class JdbcPersistentTokenRepositoryTests {

	@Mock
	private Log logger;

	private static SingleConnectionDataSource dataSource;

	private JdbcPersistentTokenRepository repo;

	private JdbcClient client;

	@BeforeAll
	public static void createDataSource() {
		dataSource = new SingleConnectionDataSource("jdbc:hsqldb:mem:tokenrepotest", "sa", "", true);
		dataSource.setDriverClassName("org.hsqldb.jdbc.JDBCDriver");
	}

	@AfterAll
	public static void clearDataSource() {
		dataSource.destroy();
		dataSource = null;
	}

	@BeforeEach
	public void populateDatabase() {
		this.client = JdbcClient.create(dataSource);
		this.client
			.sql("create table persistent_logins (username varchar(100) not null, "
					+ "series varchar(100) not null, token varchar(500) not null, last_used timestamp not null)")
			.update();
		this.repo = new JdbcPersistentTokenRepository(this.client);
		ReflectionTestUtils.setField(this.repo, "logger", this.logger);
		this.repo.initDao();
	}

	@AfterEach
	public void clearData() {
		this.client.sql("drop table persistent_logins").update();
	}

	@Test
	public void createNewTokenInsertsCorrectData() {
		Timestamp currentDate = new Timestamp(Calendar.getInstance().getTimeInMillis());
		PersistentRememberMeToken token = new PersistentRememberMeToken("joeuser", "joesseries", "atoken", currentDate);
		this.repo.createNewToken(token);
		Map<String, Object> results = this.client.sql("select * from persistent_logins").query().singleRow();
		assertThat(results).containsEntry("last_used", currentDate);
		assertThat(results).containsEntry("username", "joeuser");
		assertThat(results).containsEntry("series", "joesseries");
		assertThat(results).containsEntry("token", "atoken");
	}

	@Test
	public void retrievingTokenReturnsCorrectData() {
		this.client
			.sql("insert into persistent_logins (series, username, token, last_used) values "
					+ "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')")
			.update();
		PersistentRememberMeToken token = this.repo.getTokenForSeries("joesseries");
		assertThat(token.getUsername()).isEqualTo("joeuser");
		assertThat(token.getSeries()).isEqualTo("joesseries");
		assertThat(token.getTokenValue()).isEqualTo("atoken");
		assertThat(token.getDate()).isEqualTo(Timestamp.valueOf("2007-10-09 18:19:25.000000000"));
	}

	@Test
	public void retrievingTokenWithDuplicateSeriesReturnsNull() {
		this.client
			.sql("insert into persistent_logins (series, username, token, last_used) values "
					+ "('joesseries', 'joeuser', 'atoken2', '2007-10-19 18:19:25.000000000')")
			.update();
		this.client
			.sql("insert into persistent_logins (series, username, token, last_used) values "
					+ "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')")
			.update();
		assertThat(this.repo.getTokenForSeries("joesseries")).isNull();
	}

	// SEC-1964
	@Test
	public void retrievingTokenWithNoSeriesReturnsNull() {
		assertThat(this.repo.getTokenForSeries("missingSeries")).isNull();
		ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
		then(this.logger).should().debug(captor.capture(), any(EmptyResultDataAccessException.class));
		then(this.logger).shouldHaveNoMoreInteractions();
		assertThat(captor.getValue()).hasToString("Querying token for series 'missingSeries' returned no results.");
	}

	@Test
	public void removingUserTokensDeletesData() {
		this.client
			.sql("insert into persistent_logins (series, username, token, last_used) values "
					+ "('joesseries2', 'joeuser', 'atoken2', '2007-10-19 18:19:25.000000000')")
			.update();
		this.client
			.sql("insert into persistent_logins (series, username, token, last_used) values "
					+ "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')")
			.update();
		this.repo.removeUserTokens("joeuser");
		List<Map<String, Object>> results = this.client
			.sql("select * from persistent_logins where username = 'joeuser'")
			.query()
			.listOfRows();
		assertThat(results).isEmpty();
	}

	@Test
	public void updatingTokenModifiesTokenValueAndLastUsed() {
		Timestamp ts = new Timestamp(System.currentTimeMillis() - 1);
		this.client
			.sql("insert into persistent_logins (series, username, token, last_used) values "
					+ "('joesseries', 'joeuser', 'atoken', '" + ts + "')")
			.update();
		this.repo.updateToken("joesseries", "newtoken", new Date());
		Map<String, Object> results = this.client.sql("select * from persistent_logins where series = 'joesseries'")
			.query()
			.singleRow();
		assertThat(results).containsEntry("username", "joeuser");
		assertThat(results).containsEntry("series", "joesseries");
		assertThat(results).containsEntry("token", "newtoken");
		Date lastUsed = (Date) results.get("last_used");
		assertThat(lastUsed.getTime() > ts.getTime()).isTrue();
	}

	@Test
	public void createTableOnStartupCreatesCorrectTable() {
		this.client.sql("drop table persistent_logins").update();
		this.repo = new JdbcPersistentTokenRepository(this.client);
		this.repo.setCreateTableOnStartup(true);
		this.repo.initDao();
		this.client.sql("select username,series,token,last_used from persistent_logins").query().listOfRows();
	}

	// SEC-2879
	@Test
	public void updateUsesLastUsed() {
		JdbcClient mockClient = mock(JdbcClient.class);
		JdbcClient.StatementSpec statementSpec = mock(JdbcClient.StatementSpec.class);
		Date lastUsed = new Date(1424841314059L);
		given(mockClient.sql(anyString())).willReturn(statementSpec);
		given(statementSpec.param(any())).willReturn(statementSpec);
		JdbcPersistentTokenRepository repository = new JdbcPersistentTokenRepository(mockClient);
		repository.updateToken("series", "token", lastUsed);
		then(statementSpec).should().param(eq(lastUsed));
	}

}
