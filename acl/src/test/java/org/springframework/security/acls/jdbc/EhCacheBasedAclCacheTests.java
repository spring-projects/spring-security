package org.springframework.security.acls.jdbc;

import java.io.Serializable;

import junit.framework.Assert;
import junit.framework.TestCase;
import net.sf.ehcache.Cache;
import net.sf.ehcache.Ehcache;

import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.MockApplicationContext;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;

/**
 * Tests {@link EhCacheBasedAclCache}
 *
 * @author Andrei Stefan
 */
public class EhCacheBasedAclCacheTests extends TestCase {
    //~ Instance fields ================================================================================================
    
    AbstractXmlApplicationContext ctx;

    //~ Methods ========================================================================================================

    private Ehcache getCache() {
        this.ctx = (AbstractXmlApplicationContext) MockApplicationContext.getContext();

        return (Ehcache) ctx.getBean("eHCacheBackend");
    }
    
    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
        if (ctx != null) {
            ctx.close();
        }
    }

    public void testConstructorRejectsNullParameters() throws Exception {
        try {
            AclCache aclCache = new EhCacheBasedAclCache(null);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }
    }

    public void testMethodsRejectNullParameters() throws Exception {
        Ehcache cache = new MockEhcache();
        EhCacheBasedAclCache myCache = new EhCacheBasedAclCache(cache);

        try {
            Serializable id = null;
            myCache.evictFromCache(id);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            ObjectIdentity obj = null;
            myCache.evictFromCache(obj);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            Serializable id = null;
            myCache.getFromCache(id);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            ObjectIdentity obj = null;
            myCache.getFromCache(obj);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            MutableAcl acl = null;
            myCache.putInCache(acl);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }
    }

    public void testCacheOperationsAclWithoutParent() throws Exception {
        Ehcache cache = getCache();
        EhCacheBasedAclCache myCache = new EhCacheBasedAclCache(cache);

        ObjectIdentity identity = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });
        MutableAcl acl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());

        myCache.putInCache(acl);
        Assert.assertEquals(cache.getSize(), 2);

        // Check we can get from cache the same objects we put in
        Assert.assertEquals(myCache.getFromCache(new Long(1)), acl);
        Assert.assertEquals(myCache.getFromCache(identity), acl);

        // Put another object in cache
        ObjectIdentity identity2 = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        MutableAcl acl2 = new AclImpl(identity2, new Long(2), aclAuthorizationStrategy, new ConsoleAuditLogger());

        myCache.putInCache(acl2);
        Assert.assertEquals(cache.getSize(), 4);

        // Try to evict an entry that doesn't exist
        myCache.evictFromCache(new Long(3));
        myCache.evictFromCache(new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102)));
        Assert.assertEquals(cache.getSize(), 4);

        myCache.evictFromCache(new Long(1));
        Assert.assertEquals(cache.getSize(), 2);

        // Check the second object inserted
        Assert.assertEquals(myCache.getFromCache(new Long(2)), acl2);
        Assert.assertEquals(myCache.getFromCache(identity2), acl2);

        myCache.evictFromCache(identity2);
        Assert.assertEquals(cache.getSize(), 0);
    }
    
    public void testCacheOperationsAclWithParent() throws Exception {
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
        Assert.assertEquals(cache.getSize(), 4);

        // Check we can get from cache the same objects we put in
        Assert.assertEquals(myCache.getFromCache(new Long(1)), acl);
        Assert.assertEquals(myCache.getFromCache(identity), acl);
        Assert.assertEquals(myCache.getFromCache(new Long(2)), parentAcl);
        Assert.assertEquals(myCache.getFromCache(identityParent), parentAcl);
    }

    //~ Inner Classes ==================================================================================================

    private class MockEhcache extends Cache {
        public MockEhcache() {
            super("cache", 0, true, true, 0, 0);
        }
    }
}
