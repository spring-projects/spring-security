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

package net.sf.acegisecurity.acl.basic;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.PopulatedDatabase;
import net.sf.acegisecurity.acl.AclEntry;
import net.sf.acegisecurity.acl.basic.cache.BasicAclEntryHolder;
import net.sf.acegisecurity.acl.basic.cache.NullAclEntryCache;
import net.sf.acegisecurity.acl.basic.jdbc.JdbcDaoImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import java.util.HashMap;
import java.util.Map;


/**
 * Tests {@link BasicAclProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAclProviderTests extends TestCase {
    //~ Static fields/initializers =============================================

    public static final String OBJECT_IDENTITY = "net.sf.acegisecurity.acl.DomainObject";

    //~ Constructors ===========================================================

    public BasicAclProviderTests() {
        super();
    }

    public BasicAclProviderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BasicAclProviderTests.class);
    }

    public void testCachingUsedProperly() throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        MockCache cache = new MockCache();
        provider.setBasicAclEntryCache(cache);

        assertEquals(0, cache.getGets());
        assertEquals(0, cache.getGetsHits());
        assertEquals(0, cache.getPuts());
        assertEquals(0, cache.getBackingMap().size());

        Object object = new MockDomain(1); // has no parents
        provider.getAcls(object);

        assertEquals(1, cache.getGets());
        assertEquals(0, cache.getGetsHits());
        assertEquals(1, cache.getPuts());
        assertEquals(1, cache.getBackingMap().size());

        provider.getAcls(object);

        assertEquals(2, cache.getGets());
        assertEquals(1, cache.getGetsHits());
        assertEquals(1, cache.getPuts());
        assertEquals(1, cache.getBackingMap().size());

        object = new MockDomain(1000); // does not exist

        provider.getAcls(object);

        assertEquals(3, cache.getGets());
        assertEquals(1, cache.getGetsHits());
        assertEquals(2, cache.getPuts());
        assertEquals(2, cache.getBackingMap().size());

        provider.getAcls(object);

        assertEquals(4, cache.getGets());
        assertEquals(2, cache.getGetsHits());
        assertEquals(2, cache.getPuts());
        assertEquals(2, cache.getBackingMap().size());

        provider.getAcls(object);

        assertEquals(5, cache.getGets());
        assertEquals(3, cache.getGetsHits());
        assertEquals(2, cache.getPuts());
        assertEquals(2, cache.getBackingMap().size());
    }

    public void testExceptionThrownIfUnsupportedObjectIsSubmitted()
        throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        // this one should NOT be supported, as it has no getId() method
        assertFalse(provider.supports(new Integer(34)));

        // try anyway
        try {
            provider.getAcls(new Integer(34));
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetAclsForInstanceNotFound() throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        Object object = new MockDomain(546464646);
        AclEntry[] acls = provider.getAcls(object);
        assertNull(acls);
    }

    public void testGetAclsForInstanceWithParentLevels()
        throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        Object object = new MockDomain(6);
        AclEntry[] acls = provider.getAcls(object);
        assertEquals(2, acls.length);

        assertEquals("scott", ((BasicAclEntry) acls[0]).getRecipient());
        assertEquals("ROLE_SUPERVISOR", ((BasicAclEntry) acls[1]).getRecipient());
    }

    public void testGetAclsForInstanceWithoutParent() throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        Object object = new MockDomain(7);
        AclEntry[] acls = provider.getAcls(object);
        assertEquals(1, acls.length);
    }

    public void testGetAclsWithAuthentication() throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        Authentication scott = new UsernamePasswordAuthenticationToken("scott",
                "unused");

        Object object = new MockDomain(6);
        AclEntry[] acls = provider.getAcls(object, scott);

        assertEquals(1, acls.length);
        assertEquals("scott", ((BasicAclEntry) acls[0]).getRecipient());
    }

    public void testGettersSetters() {
        BasicAclProvider provider = new BasicAclProvider();
        assertEquals(NullAclEntryCache.class,
            provider.getBasicAclEntryCache().getClass());
        assertEquals(NamedEntityObjectIdentity.class,
            provider.getDefaultAclObjectIdentityClass());
        assertEquals(GrantedAuthorityEffectiveAclsResolver.class,
            provider.getEffectiveAclsResolver().getClass());

        provider.setBasicAclEntryCache(null);
        assertNull(provider.getBasicAclEntryCache());

        provider.setDefaultAclObjectIdentityClass(null);
        assertNull(provider.getDefaultAclObjectIdentityClass());

        provider.setEffectiveAclsResolver(null);
        assertNull(provider.getEffectiveAclsResolver());

        provider.setBasicAclDao(new MockDao());
        assertNotNull(provider.getBasicAclDao());
    }

    public void testStartupFailsIfNullAclDao() throws Exception {
        BasicAclProvider provider = new BasicAclProvider();

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfNullEffectiveAclsResolver()
        throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        provider.setEffectiveAclsResolver(null);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfNullEntryCache() throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        provider.setBasicAclEntryCache(null);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfProblemWithAclObjectIdentityClass()
        throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        // check nulls rejected
        provider.setDefaultAclObjectIdentityClass(null);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        // check non-AclObjectIdentity classes are also rejected
        provider.setDefaultAclObjectIdentityClass(String.class);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        // check AclObjectIdentity class without constructor accepting a
        // domain object is also rejected
        provider.setDefaultAclObjectIdentityClass(MockAclObjectIdentity.class);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("defaultAclObjectIdentityClass must provide a constructor that accepts the domain object instance!",
                expected.getMessage());
        }
    }

    public void testSupports() throws Exception {
        BasicAclProvider provider = new BasicAclProvider();
        provider.setBasicAclDao(makePopulatedJdbcDao());

        // this one should NOT be supported, as it has no getId() method
        assertFalse(provider.supports(new Integer(34)));

        // this one SHOULD be supported, as it has a getId() method
        assertTrue(provider.supports(new SomeDomain()));

        // this one SHOULD be supported, as it implements AclObjectIdentityAware
        assertTrue(provider.supports(new MockDomain(4)));
    }

    private JdbcDaoImpl makePopulatedJdbcDao() throws Exception {
        JdbcDaoImpl dao = new JdbcDaoImpl();
        dao.setDataSource(PopulatedDatabase.getDataSource());
        dao.afterPropertiesSet();

        return dao;
    }

    //~ Inner Classes ==========================================================

    private class MockCache implements BasicAclEntryCache {
        private Map map = new HashMap();
        private int gets = 0;
        private int getsHits = 0;
        private int puts = 0;

        public Map getBackingMap() {
            return map;
        }

        public BasicAclEntry[] getEntriesFromCache(
            AclObjectIdentity aclObjectIdentity) {
            gets++;

            Object result = map.get(aclObjectIdentity);

            if (result == null) {
                return null;
            }

            getsHits++;

            BasicAclEntryHolder holder = (BasicAclEntryHolder) result;

            return holder.getBasicAclEntries();
        }

        public int getGets() {
            return gets;
        }

        public int getGetsHits() {
            return getsHits;
        }

        public int getPuts() {
            return puts;
        }

        public void putEntriesInCache(BasicAclEntry[] basicAclEntry) {
            puts++;

            BasicAclEntryHolder holder = new BasicAclEntryHolder(basicAclEntry);
            map.put(basicAclEntry[0].getAclObjectIdentity(), holder);
        }
    }

    private class MockDao implements BasicAclDao {
        public BasicAclEntry[] getAcls(AclObjectIdentity aclObjectIdentity) {
            return null;
        }
    }

    private class MockDomain implements AclObjectIdentityAware {
        private int id;

        public MockDomain(int id) {
            this.id = id;
        }

        public AclObjectIdentity getAclObjectIdentity() {
            return new NamedEntityObjectIdentity(OBJECT_IDENTITY,
                new Integer(id).toString());
        }
    }
}
