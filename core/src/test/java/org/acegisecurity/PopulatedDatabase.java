/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;


/**
 * Singleton which provides a populated database connection for all
 * JDBC-related unit tests.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PopulatedDatabase {
    //~ Static fields/initializers =============================================

    private static DriverManagerDataSource dataSource = null;

    //~ Constructors ===========================================================

    private PopulatedDatabase() {}

    //~ Methods ================================================================

    public static DataSource getDataSource() {
        if (dataSource == null) {
            setupDataSource();
        }

        return dataSource;
    }

    private static void setupDataSource() {
        dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
        dataSource.setUrl("jdbc:hsqldb:mem:acegisecuritytest");
        dataSource.setUsername("sa");
        dataSource.setPassword("");

        JdbcTemplate template = new JdbcTemplate(dataSource);

        template.execute(
            "CREATE TABLE USERS(USERNAME VARCHAR_IGNORECASE(50) NOT NULL PRIMARY KEY,PASSWORD VARCHAR_IGNORECASE(50) NOT NULL,ENABLED BOOLEAN NOT NULL)");
        template.execute(
            "CREATE TABLE AUTHORITIES(USERNAME VARCHAR_IGNORECASE(50) NOT NULL,AUTHORITY VARCHAR_IGNORECASE(50) NOT NULL,CONSTRAINT FK_AUTHORITIES_USERS FOREIGN KEY(USERNAME) REFERENCES USERS(USERNAME))");
        template.execute(
            "CREATE UNIQUE INDEX IX_AUTH_USERNAME ON AUTHORITIES(USERNAME,AUTHORITY)");
        template.execute(
            "CREATE TABLE ACLS(OBJECT_IDENTITY VARCHAR_IGNORECASE(250) NOT NULL,RECIPIENT VARCHAR_IGNORECASE(100) NOT NULL,PARENT_OBJECT_IDENTITY VARCHAR_IGNORECASE(250),MASK INTEGER NOT NULL,ACL_CLASS VARCHAR_IGNORECASE(250) NOT NULL,CONSTRAINT PK_ACLS PRIMARY KEY(OBJECT_IDENTITY,RECIPIENT))");
        template.execute("SET IGNORECASE TRUE");
        template.execute("INSERT INTO USERS VALUES('dianne','emu',TRUE)");
        template.execute("INSERT INTO USERS VALUES('marissa','koala',TRUE)");
        template.execute("INSERT INTO USERS VALUES('peter','opal',FALSE)");
        template.execute("INSERT INTO USERS VALUES('scott','wombat',TRUE)");
        template.execute("INSERT INTO USERS VALUES('cooper','kookaburra',TRUE)");
        template.execute(
            "INSERT INTO AUTHORITIES VALUES('marissa','ROLE_TELLER')");
        template.execute(
            "INSERT INTO AUTHORITIES VALUES('marissa','ROLE_SUPERVISOR')");
        template.execute(
            "INSERT INTO AUTHORITIES VALUES('dianne','ROLE_TELLER')");
        template.execute(
            "INSERT INTO AUTHORITIES VALUES('scott','ROLE_TELLER')");
        template.execute(
            "INSERT INTO AUTHORITIES VALUES('peter','ROLE_TELLER')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:1','ROLE_SUPERVISOR',NULL,1,'net.sf.acegisecurity.acl.basic.SimpleAclEntry')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:2','marissa','net.sf.acegisecurity.acl.DomainObject:1',2,'net.sf.acegisecurity.acl.basic.SimpleAclEntry')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:2','ROLE_SUPERVISOR','net.sf.acegisecurity.acl.DomainObject:1',0,'net.sf.acegisecurity.acl.basic.SimpleAclEntry')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:3','scott','net.sf.acegisecurity.acl.DomainObject:1',14,'net.sf.acegisecurity.acl.basic.SimpleAclEntry')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:4','inheritance_marker_only','net.sf.acegisecurity.acl.DomainObject:1',0,'net.sf.acegisecurity.acl.basic.SimpleAclEntry')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:5','inheritance_marker_only','net.sf.acegisecurity.acl.DomainObject:3',0,'net.sf.acegisecurity.acl.basic.SimpleAclEntry')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:6','scott','net.sf.acegisecurity.acl.DomainObject:3',1,'net.sf.acegisecurity.acl.basic.SimpleAclEntry')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:7','scott','some.invalid.parent:1',2,'net.sf.acegisecurity.acl.basic.SimpleAclEntry')");
        template.execute(
            "INSERT INTO ACLS VALUES('net.sf.acegisecurity.acl.DomainObject:8','scott','net.sf.acegisecurity.acl.DomainObject:3',1,'some.invalid.basic.acl.entry.class.name')");
    }
}
