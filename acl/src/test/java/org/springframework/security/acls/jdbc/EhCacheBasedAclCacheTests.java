package org.springframework.security.acls.jdbc;

import java.io.Serializable;

import net.sf.ehcache.Cache;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.CacheManager;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;

import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;

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
        cacheManager.addCache(new Cache("ehcachebasedacltests", 500, false, false, 30, 30));
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
        AclCache aclCache = new EhCacheBasedAclCache(null);
        fail("It should have thrown IllegalArgumentException");
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

    @Test
    public void cacheOperationsAclWithoutParent() throws Exception {
        Ehcache cache = getCache();
        EhCacheBasedAclCache myCache = new EhCacheBasedAclCache(cache);

        ObjectIdentity identity = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });
        MutableAcl acl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());

        myCache.putInCache(acl);
        assertEquals(cache.getSize(), 2);

        // Check we can get from cache the same objects we put in
        assertEquals(myCache.getFromCache(new Long(1)), acl);
        assertEquals(myCache.getFromCache(identity), acl);

        // Put another object in cache
        ObjectIdentity identity2 = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        MutableAcl acl2 = new AclImpl(identity2, new Long(2), aclAuthorizationStrategy, new ConsoleAuditLogger());

        myCache.putInCache(acl2);
        assertEquals(cache.getSize(), 4);

        // Try to evict an entry that doesn't exist
        myCache.evictFromCache(new Long(3));
        myCache.evictFromCache(new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102)));
        assertEquals(cache.getSize(), 4);

        myCache.evictFromCache(new Long(1));
        assertEquals(cache.getSize(), 2);

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

        myCache.putInCache(acl);
        assertEquals(cache.getSize(), 4);

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
