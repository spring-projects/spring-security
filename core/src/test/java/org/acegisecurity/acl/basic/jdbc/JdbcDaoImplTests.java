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

package net.sf.acegisecurity.acl.basic.jdbc;

import junit.framework.TestCase;

import net.sf.acegisecurity.PopulatedDatabase;
import net.sf.acegisecurity.acl.basic.AclObjectIdentity;
import net.sf.acegisecurity.acl.basic.BasicAclEntry;
import net.sf.acegisecurity.acl.basic.NamedEntityObjectIdentity;

import org.springframework.jdbc.object.MappingSqlQuery;

import java.sql.ResultSet;
import java.sql.SQLException;


/**
 * Tests {@link JdbcDaoImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JdbcDaoImplTests extends TestCase {
    //~ Static fields/initializers =============================================

    public static final String OBJECT_IDENTITY = "net.sf.acegisecurity.acl.DomainObject";

    //~ Constructors ===========================================================

    public JdbcDaoImplTests() {
        super();
    }

    public JdbcDaoImplTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(JdbcDaoImplTests.class);
    }

    public void testExceptionThrownIfBasicAclEntryClassNotFound()
        throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY,
                "7");

        try {
            dao.getAcls(identity);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetsEntriesWhichExistInDatabaseAndHaveAcls()
        throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY,
                "2");
        BasicAclEntry[] acls = dao.getAcls(identity);
        assertEquals(2, acls.length);
    }

    public void testGetsEntriesWhichExistInDatabaseButHaveNoAcls()
        throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY,
                "5");
        BasicAclEntry[] acls = dao.getAcls(identity);
        assertEquals(1, acls.length);
        assertEquals(JdbcDaoImpl.RECIPIENT_USED_FOR_INHERITENCE_MARKER,
            acls[0].getRecipient());
    }

    public void testGetsEntriesWhichHaveNoParent() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY,
                "1");
        BasicAclEntry[] acls = dao.getAcls(identity);
        assertEquals(1, acls.length);
        assertNull(acls[0].getAclObjectParentIdentity());
    }

    public void testGettersSetters() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        dao.setAclsByObjectIdentity(new MockMappingSqlQuery());
        assertNotNull(dao.getAclsByObjectIdentity());

        dao.setAclsByObjectIdentityQuery("foo");
        assertEquals("foo", dao.getAclsByObjectIdentityQuery());

        dao.setObjectPropertiesQuery("foobar");
        assertEquals("foobar", dao.getObjectPropertiesQuery());
    }

    public void testNullReturnedIfEntityNotFound() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY,
                "NOT_VALID_ID");
        BasicAclEntry[] result = dao.getAcls(identity);
        assertNull(result);
    }

    public void testReturnsNullForUnNamedEntityObjectIdentity()
        throws Exception {
        JdbcDaoImpl dao = new JdbcDaoImpl();
        AclObjectIdentity identity = new AclObjectIdentity() {}
        ;

        assertNull(dao.getAcls(identity));
    }

    private JdbcDaoImpl makePopulatedJdbcDao() throws Exception {
        JdbcDaoImpl dao = new JdbcDaoImpl();
        dao.setDataSource(PopulatedDatabase.getDataSource());
        dao.afterPropertiesSet();

        return dao;
    }

    //~ Inner Classes ==========================================================

    private class MockMappingSqlQuery extends MappingSqlQuery {
        protected Object mapRow(ResultSet arg0, int arg1)
            throws SQLException {
            return null;
        }
    }
}
