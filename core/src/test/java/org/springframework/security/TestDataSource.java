package org.springframework.security;

import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.DisposableBean;

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

    public void destroy() throws Exception {
        System.out.println("Shutting down database: " + name);
        new JdbcTemplate(this).execute("SHUTDOWN");
    }
}
