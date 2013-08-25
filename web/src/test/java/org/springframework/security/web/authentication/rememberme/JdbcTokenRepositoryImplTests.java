/*
 * Copyright 2002-2012 the original author or authors.
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
package org.springframework.security.web.authentication.rememberme;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.sql.Timestamp;
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
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.util.ReflectionTestUtils;

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
        dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
    }

    @AfterClass
    public static void clearDataSource() throws Exception {
        dataSource.destroy();
        dataSource = null;
    }

    @Before
    public void populateDatabase() {
        repo = new JdbcTokenRepositoryImpl();
        ReflectionTestUtils.setField(repo, "logger", logger);
        repo.setDataSource(dataSource);
        repo.initDao();
        template = repo.getJdbcTemplate();
        template.execute("create table persistent_logins (username varchar not null, " +
                "series varchar not null, token varchar not null, last_used timestamp not null)");
    }

    @After
    public void clearData() {
        template.execute("drop table persistent_logins");
    }

    @Test
    public void createNewTokenInsertsCorrectData() {
        Date currentDate = new Date();
        PersistentRememberMeToken token = new PersistentRememberMeToken("joeuser", "joesseries", "atoken", currentDate);
        repo.createNewToken(token);

        Map<String,Object> results = template.queryForMap("select * from persistent_logins");

        assertEquals(currentDate, results.get("last_used"));
        assertEquals("joeuser", results.get("username"));
        assertEquals("joesseries", results.get("series"));
        assertEquals("atoken", results.get("token"));
    }

    @Test
    public void retrievingTokenReturnsCorrectData() {

        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')");
        PersistentRememberMeToken token = repo.getTokenForSeries("joesseries");

        assertEquals("joeuser", token.getUsername());
        assertEquals("joesseries", token.getSeries());
        assertEquals("atoken", token.getTokenValue());
        assertEquals(Timestamp.valueOf("2007-10-09 18:19:25.000000000"), token.getDate());
    }

    @Test
    public void retrievingTokenWithDuplicateSeriesReturnsNull() {
        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries', 'joeuser', 'atoken2', '2007-10-19 18:19:25.000000000')");
        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')");

//        List results = template.queryForList("select * from persistent_logins where series = 'joesseries'");

        assertNull(repo.getTokenForSeries("joesseries"));
    }

    // SEC-1964
    @Test
    public void retrievingTokenWithNoSeriesReturnsNull() {
        when(logger.isDebugEnabled()).thenReturn(true);

        assertNull(repo.getTokenForSeries("missingSeries"));

        verify(logger).isDebugEnabled();
        verify(logger).debug(eq("Querying token for series 'missingSeries' returned no results."),
                any(EmptyResultDataAccessException.class));
        verifyNoMoreInteractions(logger);
    }

    @Test
    public void removingUserTokensDeletesData() {
        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries2', 'joeuser', 'atoken2', '2007-10-19 18:19:25.000000000')");
        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')");

       // List results = template.queryForList("select * from persistent_logins where series = 'joesseries'");

        repo.removeUserTokens("joeuser");

        List<Map<String,Object>> results = template.queryForList("select * from persistent_logins where username = 'joeuser'");

        assertEquals(0, results.size());
    }

    @Test
    public void updatingTokenModifiesTokenValueAndLastUsed() {
        Timestamp ts = new Timestamp(System.currentTimeMillis() - 1);
        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries', 'joeuser', 'atoken', '" + ts.toString() + "')");
        repo.updateToken("joesseries", "newtoken", new Date());

        Map<String,Object> results = template.queryForMap("select * from persistent_logins where series = 'joesseries'");

        assertEquals("joeuser", results.get("username"));
        assertEquals("joesseries", results.get("series"));
        assertEquals("newtoken", results.get("token"));
        Date lastUsed = (Date) results.get("last_used");
        assertTrue(lastUsed.getTime() > ts.getTime());
    }

    @Test
    public void createTableOnStartupCreatesCorrectTable() {
        template.execute("drop table persistent_logins");
        repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        repo.setCreateTableOnStartup(true);
        repo.initDao();

        template.queryForList("select username,series,token,last_used from persistent_logins");
    }

}
