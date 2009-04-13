package org.springframework.security.acls.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.FieldUtils;

/**
 * Tests {@link EhCacheBasedAclCache}
 *
 * @author Andrei Stefan
 */
public class EhCacheBasedAclCacheTests {
    //~ Instance fields ================================================================================================
    private static CacheManager cacheManager;

    //~ Methods ========================================================================================================
    @BeforeClass
    public static void initCacheManaer() {
        cacheManager = new CacheManager();
        // Use disk caching immediately (to test for serialization issue reported in SEC-527)
        cacheManager.addCache(new Cache("ehcachebasedacltests", 0, true, false, 30, 30));
    }

    @AfterClass
    public static void shutdownCacheManager() {
        cacheManager.removalAll();
        cacheManager.shutdown();
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private Ehcache getCache() {
        Ehcache cache = cacheManager.getCache("ehcachebasedacltests");
        cache.removeAll();

        return cache;
    }

    @Test(expected=IllegalArgumentException.class)
    public void constructorRejectsNullParameters() throws Exception {
        new EhCacheBasedAclCache(null);
    }

    @Test
    public void methodsRejectNullParameters() throws Exception {
        Ehcache cache = new MockEhcache();
        EhCacheBasedAclCache myCache = new EhCacheBasedAclCache(cache);

        try {
            Serializable id = null;
            myCache.evictFromCache(id);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            ObjectIdentity obj = null;
            myCache.evictFromCache(obj);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            Serializable id = null;
            myCache.getFromCache(id);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            ObjectIdentity obj = null;
            myCache.getFromCache(obj);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            MutableAcl acl = null;
            myCache.putInCache(acl);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    // SEC-527
    @Test
    public void testDiskSerializationOfMutableAclObjectInstance() throws Exception {
        ObjectIdentity identity = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });
        MutableAcl acl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());

        // Serialization test
        File file = File.createTempFile("SEC_TEST", ".object");
        FileOutputStream fos = new FileOutputStream(file);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(acl);
        oos.close();

        FileInputStream fis = new FileInputStream(file);
        ObjectInputStream ois = new ObjectInputStream(fis);
        MutableAcl retrieved = (MutableAcl) ois.readObject();
        ois.close();

        assertEquals(acl, retrieved);

        Object retrieved1 = FieldUtils.getProtectedFieldValue("aclAuthorizationStrategy", retrieved);
        assertEquals(null, retrieved1);

        Object retrieved2 = FieldUtils.getProtectedFieldValue("auditLogger", retrieved);
        assertEquals(null, retrieved2);
    }

    @Test
    public void cacheOperationsAclWithoutParent() throws Exception {
        Ehcache cache = getCache();
        EhCacheBasedAclCache myCache = new EhCacheBasedAclCache(cache);

        ObjectIdentity identity = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });
        MutableAcl acl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());

        assertEquals(0, cache.getDiskStoreSize());
        myCache.putInCache(acl);
        assertEquals(cache.getSize(), 2);
        assertEquals(2, cache.getDiskStoreSize());
        assertTrue(cache.isElementOnDisk(acl.getObjectIdentity()));
        assertFalse(cache.isElementInMemory(acl.getObjectIdentity()));

        // Check we can get from cache the same objects we put in
        assertEquals(myCache.getFromCache(new Long(1)), acl);
        assertEquals(myCache.getFromCache(identity), acl);

        // Put another object in cache
        ObjectIdentity identity2 = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        MutableAcl acl2 = new AclImpl(identity2, new Long(2), aclAuthorizationStrategy, new ConsoleAuditLogger());

        myCache.putInCache(acl2);
        assertEquals(cache.getSize(), 4);
        assertEquals(4, cache.getDiskStoreSize());

        // Try to evict an entry that doesn't exist
        myCache.evictFromCache(new Long(3));
        myCache.evictFromCache(new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102)));
        assertEquals(cache.getSize(), 4);
        assertEquals(4, cache.getDiskStoreSize());

        myCache.evictFromCache(new Long(1));
        assertEquals(cache.getSize(), 2);
        assertEquals(2, cache.getDiskStoreSize());

        // Check the second object inserted
        assertEquals(myCache.getFromCache(new Long(2)), acl2);
        assertEquals(myCache.getFromCache(identity2), acl2);

        myCache.evictFromCache(identity2);
        assertEquals(cache.getSize(), 0);
    }

    @Test
    public void cacheOperationsAclWithParent() throws Exception {
        Ehcache cache = getCache();
        EhCacheBasedAclCache myCache = new EhCacheBasedAclCache(cache);

        Authentication auth = new TestingAuthenticationToken("user", "password", new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_GENERAL") });
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity identity = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity identityParent = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });
        MutableAcl acl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());
        MutableAcl parentAcl = new AclImpl(identityParent, new Long(2), aclAuthorizationStrategy, new ConsoleAuditLogger());

        acl.setParent(parentAcl);

        assertEquals(0, cache.getDiskStoreSize());
        myCache.putInCache(acl);
        assertEquals(cache.getSize(), 4);
        assertEquals(4, cache.getDiskStoreSize());
        assertTrue(cache.isElementOnDisk(acl.getObjectIdentity()));
        assertFalse(cache.isElementInMemory(acl.getObjectIdentity()));

        // Check we can get from cache the same objects we put in
        assertEquals(myCache.getFromCache(new Long(1)), acl);
        assertEquals(myCache.getFromCache(identity), acl);
        assertEquals(myCache.getFromCache(new Long(2)), parentAcl);
        assertEquals(myCache.getFromCache(identityParent), parentAcl);
    }

    //~ Inner Classes ==================================================================================================

    private class MockEhcache extends Cache {
        public MockEhcache() {
            super("cache", 0, true, true, 0, 0);
        }
    }
}
