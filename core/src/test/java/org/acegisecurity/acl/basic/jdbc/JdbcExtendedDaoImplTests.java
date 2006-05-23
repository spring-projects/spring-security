/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity.acl.basic.jdbc;

import junit.framework.TestCase;

import org.acegisecurity.PopulatedDatabase;

import org.acegisecurity.acl.basic.AclObjectIdentity;
import org.acegisecurity.acl.basic.BasicAclEntry;
import org.acegisecurity.acl.basic.NamedEntityObjectIdentity;
import org.acegisecurity.acl.basic.SimpleAclEntry;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DataRetrievalFailureException;

import org.springframework.jdbc.object.MappingSqlQuery;

import java.sql.ResultSet;
import java.sql.SQLException;


/**
 * Tests {@link JdbcExtendedDaoImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JdbcExtendedDaoImplTests extends TestCase {
    //~ Static fields/initializers =====================================================================================

    public static final String OBJECT_IDENTITY = "org.acegisecurity.acl.DomainObject";

    //~ Constructors ===================================================================================================

    public JdbcExtendedDaoImplTests() {
        super();
    }

    public JdbcExtendedDaoImplTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(JdbcExtendedDaoImplTests.class);
    }

    private JdbcExtendedDaoImpl makePopulatedJdbcDao()
        throws Exception {
        JdbcExtendedDaoImpl dao = new JdbcExtendedDaoImpl();
        dao.setDataSource(PopulatedDatabase.getDataSource());
        dao.afterPropertiesSet();

        return dao;
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testChangeMask() throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "204");
        AclObjectIdentity parentIdentity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "1");

        // Create a BasicAclEntry for this AclObjectIdentity
        SimpleAclEntry simpleAcl1 = new SimpleAclEntry("marissa", identity, parentIdentity, SimpleAclEntry.CREATE);
        dao.create(simpleAcl1);

        // Create another BasicAclEntry for this AclObjectIdentity
        SimpleAclEntry simpleAcl2 = new SimpleAclEntry("scott", identity, parentIdentity, SimpleAclEntry.READ);
        dao.create(simpleAcl2);

        // Check creation was successful
        BasicAclEntry[] acls = dao.getAcls(identity);
        assertEquals(2, acls.length);
        assertEquals(SimpleAclEntry.CREATE, acls[0].getMask());
        assertEquals(SimpleAclEntry.READ, acls[1].getMask());

        // Attempt to change mask
        dao.changeMask(identity, "marissa", new Integer(SimpleAclEntry.ADMINISTRATION));
        dao.changeMask(identity, "scott", new Integer(SimpleAclEntry.NOTHING));
        acls = dao.getAcls(identity);
        assertEquals(2, acls.length);
        assertEquals("marissa", acls[0].getRecipient());
        assertEquals(SimpleAclEntry.ADMINISTRATION, acls[0].getMask());
        assertEquals("scott", acls[1].getRecipient());
        assertEquals(SimpleAclEntry.NOTHING, acls[1].getMask());
    }

    public void testChangeMaskThrowsExceptionWhenExistingRecordNotFound()
        throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "205");
        AclObjectIdentity parentIdentity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "1");

        // Create at least one record for this AclObjectIdentity
        SimpleAclEntry simpleAcl1 = new SimpleAclEntry("marissa", identity, parentIdentity, SimpleAclEntry.CREATE);
        dao.create(simpleAcl1);

        // Attempt to change mask, but for a recipient we don't have
        try {
            dao.changeMask(identity, "scott", new Integer(SimpleAclEntry.ADMINISTRATION));
            fail("Should have thrown DataRetrievalFailureException");
        } catch (DataRetrievalFailureException expected) {
            assertTrue(true);
        }
    }

    public void testConvertAclObjectIdentity() throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();

        try {
            dao.convertAclObjectIdentityToString(new AclObjectIdentity() {
                    // not a NamedEntityObjectIdentity
                });
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testCreationOfIdentityThenAclInSeparateInvocations()
        throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "206");
        AclObjectIdentity parentIdentity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "1");

        // Create just the object identity (NB: recipient and mask is null)
        SimpleAclEntry simpleAcl1 = new SimpleAclEntry();
        simpleAcl1.setAclObjectIdentity(identity);
        simpleAcl1.setAclObjectParentIdentity(parentIdentity);
        dao.create(simpleAcl1);

        // Delete it
        dao.delete(identity);
    }

    public void testDeletionOfAllRecipients() throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "203");

        // Create a BasicAclEntry for this AclObjectIdentity
        SimpleAclEntry simpleAcl1 = new SimpleAclEntry("marissa", identity, null, SimpleAclEntry.CREATE);
        dao.create(simpleAcl1);

        // Create another BasicAclEntry for this AclObjectIdentity
        SimpleAclEntry simpleAcl2 = new SimpleAclEntry("scott", identity, null, SimpleAclEntry.READ);
        dao.create(simpleAcl2);

        // Check creation was successful
        BasicAclEntry[] acls = dao.getAcls(identity);
        assertEquals(2, acls.length);

        // Attempt deletion and check delete successful
        dao.delete(identity);
        assertNull(dao.getAcls(identity));
    }

    public void testDeletionOfSpecificRecipient() throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "202");
        AclObjectIdentity parentIdentity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "1");

        // Create a BasicAclEntry for this AclObjectIdentity
        SimpleAclEntry simpleAcl1 = new SimpleAclEntry("marissa", identity, parentIdentity, SimpleAclEntry.CREATE);
        dao.create(simpleAcl1);

        // Create another BasicAclEntry for this AclObjectIdentity
        SimpleAclEntry simpleAcl2 = new SimpleAclEntry("scott", identity, parentIdentity, SimpleAclEntry.READ);
        dao.create(simpleAcl2);

        // Check creation was successful
        BasicAclEntry[] acls = dao.getAcls(identity);
        assertEquals(2, acls.length);

        // Attempt deletion and check delete successful
        dao.delete(identity, "scott");
        acls = dao.getAcls(identity);
        assertEquals(1, acls.length);
        assertEquals(simpleAcl1.getRecipient(), acls[0].getRecipient());
    }

    public void testGettersSetters() throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();

        assertNotNull(dao.getAclObjectIdentityDelete());
        dao.setAclObjectIdentityDelete(null);
        assertNull(dao.getAclObjectIdentityDelete());

        assertNotNull(dao.getAclObjectIdentityInsert());
        dao.setAclObjectIdentityInsert(null);
        assertNull(dao.getAclObjectIdentityInsert());

        assertNotNull(dao.getAclPermissionDelete());
        dao.setAclPermissionDelete(null);
        assertNull(dao.getAclPermissionDelete());

        assertNotNull(dao.getAclPermissionInsert());
        dao.setAclPermissionInsert(null);
        assertNull(dao.getAclPermissionInsert());

        assertNotNull(dao.getAclPermissionUpdate());
        dao.setAclPermissionUpdate(null);
        assertNull(dao.getAclPermissionUpdate());

        assertNotNull(dao.getAclsByObjectIdentity());
        dao.setAclsByObjectIdentity(null);
        assertNull(dao.getAclsByObjectIdentity());

        assertNotNull(dao.getLookupPermissionIdMapping());
        dao.setLookupPermissionIdMapping(null);
        assertNull(dao.getLookupPermissionIdMapping());

        assertNotNull(dao.getAclObjectIdentityDeleteStatement());
        dao.setAclObjectIdentityDeleteStatement("SELECT ...");
        assertEquals("SELECT ...", dao.getAclObjectIdentityDeleteStatement());

        assertNotNull(dao.getAclObjectIdentityInsertStatement());
        dao.setAclObjectIdentityInsertStatement("SELECT ...");
        assertEquals("SELECT ...", dao.getAclObjectIdentityInsertStatement());

        assertNotNull(dao.getAclPermissionDeleteStatement());
        dao.setAclPermissionDeleteStatement("SELECT ...");
        assertEquals("SELECT ...", dao.getAclPermissionDeleteStatement());

        assertNotNull(dao.getAclPermissionInsertStatement());
        dao.setAclPermissionInsertStatement("SELECT ...");
        assertEquals("SELECT ...", dao.getAclPermissionInsertStatement());

        assertNotNull(dao.getAclPermissionUpdateStatement());
        dao.setAclPermissionUpdateStatement("SELECT ...");
        assertEquals("SELECT ...", dao.getAclPermissionUpdateStatement());

        assertNotNull(dao.getAclsByObjectIdentityQuery());
        dao.setAclsByObjectIdentityQuery("SELECT ...");
        assertEquals("SELECT ...", dao.getAclsByObjectIdentityQuery());

        assertNotNull(dao.getLookupPermissionIdQuery());
        dao.setLookupPermissionIdQuery("SELECT ...");
        assertEquals("SELECT ...", dao.getLookupPermissionIdQuery());
    }

    public void testNormalCreationAndDuplicateDetection()
        throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "200");
        AclObjectIdentity parentIdentity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "1");

        // Create a BasicAclEntry for this AclObjectIdentity
        SimpleAclEntry simpleAcl1 = new SimpleAclEntry("marissa", identity, parentIdentity, SimpleAclEntry.CREATE);
        dao.create(simpleAcl1);

        // Create another BasicAclEntry for this AclObjectIdentity
        SimpleAclEntry simpleAcl2 = new SimpleAclEntry("scott", identity, parentIdentity, SimpleAclEntry.READ);
        dao.create(simpleAcl2);

        // Check creation was successful
        BasicAclEntry[] acls = dao.getAcls(identity);
        assertEquals(2, acls.length);
        assertEquals(simpleAcl1.getRecipient(), acls[0].getRecipient());
        assertEquals(simpleAcl1.getMask(), acls[0].getMask());
        assertEquals(simpleAcl2.getRecipient(), acls[1].getRecipient());
        assertEquals(simpleAcl2.getMask(), acls[1].getMask());

        // Check it rejects an attempt to create another identical entry
        try {
            dao.create(simpleAcl1);
            fail("Should have thrown DataIntegrityViolationException");
        } catch (DataIntegrityViolationException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsInvalidParent() throws Exception {
        JdbcExtendedDaoImpl dao = makePopulatedJdbcDao();
        AclObjectIdentity identity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "201");
        AclObjectIdentity parentIdentity = new NamedEntityObjectIdentity(OBJECT_IDENTITY, "987987987987986");
        SimpleAclEntry simpleAcl = new SimpleAclEntry("marissa", identity, parentIdentity, SimpleAclEntry.CREATE);

        try {
            dao.create(simpleAcl);
            fail("Should have thrown DataRetrievalFailureException");
        } catch (DataRetrievalFailureException expected) {
            assertTrue(true);
        }
    }

    //~ Inner Classes ==================================================================================================

    private class MockMappingSqlQuery extends MappingSqlQuery {
        protected Object mapRow(ResultSet arg0, int arg1)
            throws SQLException {
            return null;
        }
    }
}
