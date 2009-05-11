package org.springframework.security.acls.jdbc;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import junit.framework.Assert;
import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.util.FileCopyUtils;

/**
 * Tests {@link BasicLookupStrategy}
 *
 * @author Andrei Stefan
 */
public class BasicLookupStrategyTests {

    private static final Sid BEN_SID = new PrincipalSid("ben");
    private static final String TARGET_CLASS = "org.springframework.security.acls.TargetObject";

    //~ Instance fields ================================================================================================

    private static JdbcTemplate jdbcTemplate;
    private BasicLookupStrategy strategy;
    private static SingleConnectionDataSource dataSource;
    private static CacheManager cacheManager;

    //~ Methods ========================================================================================================
    @BeforeClass
    public static void initCacheManaer() {
        cacheManager = new CacheManager();
        cacheManager.addCache(new Cache("basiclookuptestcache", 500, false, false, 30, 30));
    }

    @BeforeClass
    public static void createDatabase() throws Exception {
        dataSource = new SingleConnectionDataSource("jdbc:hsqldb:mem:lookupstrategytest", "sa", "", true);
        dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
        jdbcTemplate = new JdbcTemplate(dataSource);

        Resource resource = new ClassPathResource("createAclSchema.sql");
        String sql = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
        jdbcTemplate.execute(sql);
    }

    @AfterClass
    public static void dropDatabase() throws Exception {
        dataSource.destroy();
    }

    @AfterClass
    public static void shutdownCacheManager() {
        cacheManager.removalAll();
        cacheManager.shutdown();
    }

    @Before
    public void populateDatabase() {
        String query = "INSERT INTO acl_sid(ID,PRINCIPAL,SID) VALUES (1,1,'ben');"
                + "INSERT INTO acl_class(ID,CLASS) VALUES (2,'" + TARGET_CLASS + "');"
                + "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (1,2,100,null,1,1);"
                + "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (2,2,101,1,1,1);"
                + "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (3,2,102,2,1,1);"
                + "INSERT INTO acl_entry(ID,ACL_OBJECT_IDENTITY,ACE_ORDER,SID,MASK,GRANTING,AUDIT_SUCCESS,AUDIT_FAILURE) VALUES (1,1,0,1,1,1,0,0);"
                + "INSERT INTO acl_entry(ID,ACL_OBJECT_IDENTITY,ACE_ORDER,SID,MASK,GRANTING,AUDIT_SUCCESS,AUDIT_FAILURE) VALUES (2,1,1,1,2,0,0,0);"
                + "INSERT INTO acl_entry(ID,ACL_OBJECT_IDENTITY,ACE_ORDER,SID,MASK,GRANTING,AUDIT_SUCCESS,AUDIT_FAILURE) VALUES (3,2,0,1,8,1,0,0);"
                + "INSERT INTO acl_entry(ID,ACL_OBJECT_IDENTITY,ACE_ORDER,SID,MASK,GRANTING,AUDIT_SUCCESS,AUDIT_FAILURE) VALUES (4,3,0,1,8,0,0,0);";
        jdbcTemplate.execute(query);
    }

    @Before
    public void initializeBeans() {
        EhCacheBasedAclCache cache = new EhCacheBasedAclCache(getCache());
        AclAuthorizationStrategy authorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_ADMINISTRATOR"), new GrantedAuthorityImpl("ROLE_ADMINISTRATOR"),
                new GrantedAuthorityImpl("ROLE_ADMINISTRATOR") });
        strategy = new BasicLookupStrategy(dataSource, cache, authorizationStrategy, new ConsoleAuditLogger());
    }

    @After
    public void emptyDatabase() {
        String query = "DELETE FROM acl_entry;" + "DELETE FROM acl_object_identity WHERE ID = 7;"
                + "DELETE FROM acl_object_identity WHERE ID = 6;" + "DELETE FROM acl_object_identity WHERE ID = 5;"
                + "DELETE FROM acl_object_identity WHERE ID = 4;" + "DELETE FROM acl_object_identity WHERE ID = 3;"
                + "DELETE FROM acl_object_identity WHERE ID = 2;" + "DELETE FROM acl_object_identity WHERE ID = 1;"
                + "DELETE FROM acl_class;" + "DELETE FROM acl_sid;";
        jdbcTemplate.execute(query);
    }

    private Ehcache getCache() {
        Ehcache cache = cacheManager.getCache("basiclookuptestcache");
        cache.removeAll();
        return cache;
    }

    @Test
    public void testAclsRetrievalWithDefaultBatchSize() throws Exception {
        ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(101));
        // Deliberately use an integer for the child, to reproduce bug report in SEC-819
        ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, new Integer(102));

        Map<ObjectIdentity, Acl> map = this.strategy.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);
        checkEntries(topParentOid, middleParentOid, childOid, map);
    }

    @Test
    public void testAclsRetrievalFromCacheOnly() throws Exception {
        ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Integer(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(101));
        ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(102));

        // Objects were put in cache
        strategy.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);

        // Let's empty the database to force acls retrieval from cache
        emptyDatabase();
        Map<ObjectIdentity, Acl> map = this.strategy.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);

        checkEntries(topParentOid, middleParentOid, childOid, map);
    }

    @Test
    public void testAclsRetrievalWithCustomBatchSize() throws Exception {
        ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Integer(101));
        ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(102));

        // Set a batch size to allow multiple database queries in order to retrieve all acls
        ((BasicLookupStrategy) this.strategy).setBatchSize(1);
        Map<ObjectIdentity, Acl> map = this.strategy.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);
        checkEntries(topParentOid, middleParentOid, childOid, map);
    }

    private void checkEntries(ObjectIdentity topParentOid, ObjectIdentity middleParentOid, ObjectIdentity childOid,
            Map<ObjectIdentity, Acl> map) throws Exception {
        Assert.assertEquals(3, map.size());

        MutableAcl topParent = (MutableAcl) map.get(topParentOid);
        MutableAcl middleParent = (MutableAcl) map.get(middleParentOid);
        MutableAcl child = (MutableAcl) map.get(childOid);

        // Check the retrieved versions has IDs
        Assert.assertNotNull(topParent.getId());
        Assert.assertNotNull(middleParent.getId());
        Assert.assertNotNull(child.getId());

        // Check their parents were correctly retrieved
        Assert.assertNull(topParent.getParentAcl());
        Assert.assertEquals(topParentOid, middleParent.getParentAcl().getObjectIdentity());
        Assert.assertEquals(middleParentOid, child.getParentAcl().getObjectIdentity());

        // Check their ACEs were correctly retrieved
        Assert.assertEquals(2, topParent.getEntries().size());
        Assert.assertEquals(1, middleParent.getEntries().size());
        Assert.assertEquals(1, child.getEntries().size());

        // Check object identities were correctly retrieved
        Assert.assertEquals(topParentOid, topParent.getObjectIdentity());
        Assert.assertEquals(middleParentOid, middleParent.getObjectIdentity());
        Assert.assertEquals(childOid, child.getObjectIdentity());

        // Check each entry
        Assert.assertTrue(topParent.isEntriesInheriting());
        Assert.assertEquals(topParent.getId(), new Long(1));
        Assert.assertEquals(topParent.getOwner(), new PrincipalSid("ben"));
        Assert.assertEquals(topParent.getEntries().get(0).getId(), new Long(1));
        Assert.assertEquals(topParent.getEntries().get(0).getPermission(), BasePermission.READ);
        Assert.assertEquals(topParent.getEntries().get(0).getSid(), new PrincipalSid("ben"));
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries().get(0)).isAuditFailure());
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries().get(0)).isAuditSuccess());
        Assert.assertTrue(((AuditableAccessControlEntry) topParent.getEntries().get(0)).isGranting());

        Assert.assertEquals(topParent.getEntries().get(1).getId(), new Long(2));
        Assert.assertEquals(topParent.getEntries().get(1).getPermission(), BasePermission.WRITE);
        Assert.assertEquals(topParent.getEntries().get(1).getSid(), new PrincipalSid("ben"));
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries().get(1)).isAuditFailure());
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries().get(1)).isAuditSuccess());
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries().get(1)).isGranting());

        Assert.assertTrue(middleParent.isEntriesInheriting());
        Assert.assertEquals(middleParent.getId(), new Long(2));
        Assert.assertEquals(middleParent.getOwner(), new PrincipalSid("ben"));
        Assert.assertEquals(middleParent.getEntries().get(0).getId(), new Long(3));
        Assert.assertEquals(middleParent.getEntries().get(0).getPermission(), BasePermission.DELETE);
        Assert.assertEquals(middleParent.getEntries().get(0).getSid(), new PrincipalSid("ben"));
        Assert.assertFalse(((AuditableAccessControlEntry) middleParent.getEntries().get(0)).isAuditFailure());
        Assert.assertFalse(((AuditableAccessControlEntry) middleParent.getEntries().get(0)).isAuditSuccess());
        Assert.assertTrue(((AuditableAccessControlEntry) middleParent.getEntries().get(0)).isGranting());

        Assert.assertTrue(child.isEntriesInheriting());
        Assert.assertEquals(child.getId(), new Long(3));
        Assert.assertEquals(child.getOwner(), new PrincipalSid("ben"));
        Assert.assertEquals(child.getEntries().get(0).getId(), new Long(4));
        Assert.assertEquals(child.getEntries().get(0).getPermission(), BasePermission.DELETE);
        Assert.assertEquals(child.getEntries().get(0).getSid(), new PrincipalSid("ben"));
        Assert.assertFalse(((AuditableAccessControlEntry) child.getEntries().get(0)).isAuditFailure());
        Assert.assertFalse(((AuditableAccessControlEntry) child.getEntries().get(0)).isAuditSuccess());
        Assert.assertFalse((child.getEntries().get(0)).isGranting());
    }

    @Test
    public void testAllParentsAreRetrievedWhenChildIsLoaded() throws Exception {
        String query = "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (4,2,103,1,1,1);";
        jdbcTemplate.execute(query);

        ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Integer(101));
        ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(102));
        ObjectIdentity middleParent2Oid = new ObjectIdentityImpl(TARGET_CLASS, new Long(103));

        // Retrieve the child
        Map<ObjectIdentity, Acl> map = this.strategy.readAclsById(Arrays.asList(childOid), null);

        // Check that the child and all its parents were retrieved
        Assert.assertNotNull(map.get(childOid));
        Assert.assertEquals(childOid, ((Acl) map.get(childOid)).getObjectIdentity());
        Assert.assertNotNull(map.get(middleParentOid));
        Assert.assertEquals(middleParentOid, ((Acl) map.get(middleParentOid)).getObjectIdentity());
        Assert.assertNotNull(map.get(topParentOid));
        Assert.assertEquals(topParentOid, ((Acl) map.get(topParentOid)).getObjectIdentity());

        // The second parent shouldn't have been retrieved
        Assert.assertNull(map.get(middleParent2Oid));
    }

    /**
     * Test created from SEC-590.
     */
    @Test
    public void testReadAllObjectIdentitiesWhenLastElementIsAlreadyCached() throws Exception {
        String query = "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (4,2,104,null,1,1);"
                + "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (5,2,105,4,1,1);"
                + "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (6,2,106,4,1,1);"
                + "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (7,2,107,5,1,1);"
                + "INSERT INTO acl_entry(ID,ACL_OBJECT_IDENTITY,ACE_ORDER,SID,MASK,GRANTING,AUDIT_SUCCESS,AUDIT_FAILURE) VALUES (5,4,0,1,1,1,0,0)";
        jdbcTemplate.execute(query);

        ObjectIdentity grandParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(104));
        ObjectIdentity parent1Oid = new ObjectIdentityImpl(TARGET_CLASS, new Long(105));
        ObjectIdentity parent2Oid = new ObjectIdentityImpl(TARGET_CLASS, new Integer(106));
        ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, new Integer(107));

        // First lookup only child, thus populating the cache with grandParent, parent1 and child
        List<Permission> checkPermission = Arrays.asList(BasePermission.READ);
        List<Sid> sids = Arrays.asList(BEN_SID);
        List<ObjectIdentity> childOids = Arrays.asList(childOid);

        strategy.setBatchSize(6);
        Map<ObjectIdentity, Acl> foundAcls = strategy.readAclsById(childOids, sids);

        Acl foundChildAcl = (Acl) foundAcls.get(childOid);
        Assert.assertNotNull(foundChildAcl);
        Assert.assertTrue(foundChildAcl.isGranted(checkPermission, sids, false));

        // Search for object identities has to be done in the following order: last element have to be one which
        // is already in cache and the element before it must not be stored in cache
        List<ObjectIdentity> allOids = Arrays.asList(grandParentOid, parent1Oid, parent2Oid, childOid);
        try {
            foundAcls = strategy.readAclsById(allOids, sids);
            Assert.assertTrue(true);
        } catch (NotFoundException notExpected) {
            Assert.fail("It shouldn't have thrown NotFoundException");
        }

        Acl foundParent2Acl = (Acl) foundAcls.get(parent2Oid);
        Assert.assertNotNull(foundParent2Acl);
        Assert.assertTrue(foundParent2Acl.isGranted(checkPermission, sids, false));
    }

    @Test(expected=IllegalArgumentException.class)
    public void nullOwnerIsNotSupported() {
        String query = "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (4,2,104,null,null,1);";

        jdbcTemplate.execute(query);

        ObjectIdentity oid = new ObjectIdentityImpl(TARGET_CLASS, new Long(104));

        strategy.readAclsById(Arrays.asList(oid), Arrays.asList(BEN_SID));
    }

}
