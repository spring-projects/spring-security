package org.springframework.security.acls.jdbc;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.FieldUtils;

import java.io.*;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Tests {@link org.springframework.security.acls.domain.EhCacheBasedAclCache}
 *
 * @author Andrei Stefan
 */
public class SpringCacheBasedAclCacheTests {
    private static final String TARGET_CLASS = "org.springframework.security.acls.TargetObject";

    private static CacheManager cacheManager;

    @BeforeClass
    public static void initCacheManaer() {
        cacheManager = new ConcurrentMapCacheManager();
        // Use disk caching immediately (to test for serialization issue reported in SEC-527)
        cacheManager.getCache("springcasebasedacltests");
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private Cache getCache() {
        Cache cache = cacheManager.getCache("springcasebasedacltests");
        cache.clear();
        return cache;
    }

    @Test(expected=IllegalArgumentException.class)
    public void constructorRejectsNullParameters() throws Exception {
        new SpringCacheBasedAclCache(null, null, null);
    }

    @Test
    public void cacheOperationsAclWithoutParent() throws Exception {
        Cache cache = getCache();
        Map realCache = (Map) cache.getNativeCache();
        ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(100));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
                new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority("ROLE_AUDITING"),
                new SimpleGrantedAuthority("ROLE_GENERAL"));
        AuditLogger auditLogger = new ConsoleAuditLogger();

        PermissionGrantingStrategy permissionGrantingStrategy = new DefaultPermissionGrantingStrategy(auditLogger);
        SpringCacheBasedAclCache myCache = new SpringCacheBasedAclCache(cache, permissionGrantingStrategy, aclAuthorizationStrategy);
        MutableAcl acl = new AclImpl(identity, Long.valueOf(1), aclAuthorizationStrategy, auditLogger);

        assertEquals(0, realCache.size());
        myCache.putInCache(acl);

        // Check we can get from cache the same objects we put in
        assertEquals(myCache.getFromCache(Long.valueOf(1)), acl);
        assertEquals(myCache.getFromCache(identity), acl);

        // Put another object in cache
        ObjectIdentity identity2 = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(101));
        MutableAcl acl2 = new AclImpl(identity2, Long.valueOf(2), aclAuthorizationStrategy, new ConsoleAuditLogger());

        myCache.putInCache(acl2);

        // Try to evict an entry that doesn't exist
        myCache.evictFromCache(Long.valueOf(3));
        myCache.evictFromCache(new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(102)));
        assertEquals(realCache.size(), 4);

        myCache.evictFromCache(Long.valueOf(1));
        assertEquals(realCache.size(), 2);

        // Check the second object inserted
        assertEquals(myCache.getFromCache(Long.valueOf(2)), acl2);
        assertEquals(myCache.getFromCache(identity2), acl2);

        myCache.evictFromCache(identity2);
        assertEquals(realCache.size(), 0);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void cacheOperationsAclWithParent() throws Exception {
        Cache cache = getCache();
        Map realCache = (Map) cache.getNativeCache();

        Authentication auth = new TestingAuthenticationToken("user", "password", "ROLE_GENERAL");
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(1));
        ObjectIdentity identityParent = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(2));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
                new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority("ROLE_AUDITING"),
                new SimpleGrantedAuthority("ROLE_GENERAL"));
        AuditLogger auditLogger = new ConsoleAuditLogger();

        PermissionGrantingStrategy permissionGrantingStrategy = new DefaultPermissionGrantingStrategy(auditLogger);
        SpringCacheBasedAclCache myCache = new SpringCacheBasedAclCache(cache, permissionGrantingStrategy, aclAuthorizationStrategy);

        MutableAcl acl = new AclImpl(identity, Long.valueOf(1), aclAuthorizationStrategy, auditLogger);
        MutableAcl parentAcl = new AclImpl(identityParent, Long.valueOf(2), aclAuthorizationStrategy, auditLogger);

        acl.setParent(parentAcl);

        assertEquals(0, realCache.size());
        myCache.putInCache(acl);
        assertEquals(realCache.size(), 4);

        // Check we can get from cache the same objects we put in
        AclImpl aclFromCache = (AclImpl) myCache.getFromCache(Long.valueOf(1));
        assertEquals(acl, aclFromCache);
        // SEC-951 check transient fields are set on parent
        assertNotNull(FieldUtils.getFieldValue(aclFromCache.getParentAcl(), "aclAuthorizationStrategy"));
        assertNotNull(FieldUtils.getFieldValue(aclFromCache.getParentAcl(), "permissionGrantingStrategy"));
        assertEquals(acl, myCache.getFromCache(identity));
        assertNotNull(FieldUtils.getFieldValue(aclFromCache, "aclAuthorizationStrategy"));
        AclImpl parentAclFromCache = (AclImpl) myCache.getFromCache(Long.valueOf(2));
        assertEquals(parentAcl, parentAclFromCache);
        assertNotNull(FieldUtils.getFieldValue(parentAclFromCache, "aclAuthorizationStrategy"));
        assertEquals(parentAcl, myCache.getFromCache(identityParent));
    }

    //~ Inner Classes ==================================================================================================

    private class MockCache implements Cache {

        @Override
        public String getName() {
            return "mockcache";
        }

        @Override
        public Object getNativeCache() {
            return null;
        }

        @Override
        public ValueWrapper get(Object key) {
            return null;
        }

        @Override
        public void put(Object key, Object value) {}

        @Override
        public void evict(Object key) {}

        @Override
        public void clear() {}
    }
}
