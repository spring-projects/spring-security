package org.springframework.security.web.authentication.rememberme;

import org.springframework.security.TestDataSource;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.jdbc.core.JdbcTemplate;

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * @author Luke Taylor
 * @version $Id$
 */
@SuppressWarnings("unchecked")
public class JdbcTokenRepositoryImplTests {
    private static TestDataSource dataSource;
    private JdbcTokenRepositoryImpl repo;
    private JdbcTemplate template;

    @BeforeClass
    public static void createDataSource() {
        dataSource = new TestDataSource("tokenrepotest");
    }

    @AfterClass
    public static void clearDataSource() throws Exception {
        dataSource.destroy();
        dataSource = null;
    }

    @Before
    public void populateDatabase() {
        repo = new JdbcTokenRepositoryImpl();
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

    @Test
    public void removingUserTokensDeletesData() {
        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries2', 'joeuser', 'atoken2', '2007-10-19 18:19:25.000000000')");
        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries', 'joeuser', 'atoken', '2007-10-09 18:19:25.000000000')");

       // List results = template.queryForList("select * from persistent_logins where series = 'joesseries'");

        repo.removeUserTokens("joeuser");

        List results = template.queryForList("select * from persistent_logins where username = 'joeuser'");

        assertEquals(0, results.size());
    }

    @Test
    public void updatingTokenModifiesTokenValueAndLastUsed() {
        Timestamp ts = new Timestamp(System.currentTimeMillis() - 1);
        template.execute("insert into persistent_logins (series, username, token, last_used) values " +
                "('joesseries', 'joeuser', 'atoken', '" + ts.toString() + "')");
        repo.updateToken("joesseries", "newtoken", new Date());

        Map results = template.queryForMap("select * from persistent_logins where series = 'joesseries'");

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
