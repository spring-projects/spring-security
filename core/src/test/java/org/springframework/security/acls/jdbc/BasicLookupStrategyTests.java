package org.springframework.security.acls.jdbc;

import java.util.Map;

import junit.framework.Assert;
import net.sf.ehcache.Ehcache;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.AfterClass;

import org.springframework.context.ApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.MockApplicationContext;
import org.springframework.security.TestDataSource;
import org.springframework.security.acls.AuditableAccessControlEntry;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.util.FileCopyUtils;

/**
 * Tests {@link BasicLookupStrategy}
 * 
 * @author Andrei Stefan
 */
public class BasicLookupStrategyTests {
    private static JdbcTemplate jdbcTemplate;

    private LookupStrategy strategy;

    private static TestDataSource dataSource;

    //~ Methods ========================================================================================================

    @BeforeClass
    public static void createDatabase() throws Exception {
        dataSource = new TestDataSource("lookupstrategytest");
        jdbcTemplate = new JdbcTemplate(dataSource);

        Resource resource = new ClassPathResource("org/springframework/security/acls/jdbc/testData.sql");
        String sql = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
        jdbcTemplate.execute(sql);
    }

    @AfterClass
    public static void dropDatabase() throws Exception {
        dataSource.destroy();
    }    

    @Before
    public void populateDatabase() {
        String query = "INSERT INTO acl_sid(ID,PRINCIPAL,SID) VALUES (1,1,'ben');"
                + "INSERT INTO acl_class(ID,CLASS) VALUES (2,'org.springframework.security.TargetObject');"
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
        String query = "DELETE FROM acl_entry;" + "DELETE FROM acl_object_identity WHERE ID = 3;"
                + "DELETE FROM acl_object_identity WHERE ID = 2;" + "DELETE FROM acl_object_identity WHERE ID = 1;"
                + "DELETE FROM acl_class;" + "DELETE FROM acl_sid;";
        jdbcTemplate.execute(query);
    }

    private Ehcache getCache() {
        ApplicationContext ctx = MockApplicationContext.getContext();
        return (Ehcache) ctx.getBean("eHCacheBackend");
    }

    @Test
    public void testAclsRetrievalWithDefaultBatchSize() throws Exception {
        ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        ObjectIdentity childOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102));

        Map map = this.strategy.readAclsById(new ObjectIdentity[] { topParentOid, middleParentOid, childOid }, null);
        checkEntries(topParentOid, middleParentOid, childOid, map);
    }

    @Test
    public void testAclsRetrievalFromCacheOnly() throws Exception {
        ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        ObjectIdentity childOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102));

        // Objects were put in cache
        strategy.readAclsById(new ObjectIdentity[] { topParentOid, middleParentOid, childOid }, null);

        // Let's empty the database to force acls retrieval from cache
        emptyDatabase();
        Map map = this.strategy.readAclsById(new ObjectIdentity[] { topParentOid, middleParentOid, childOid }, null);

        checkEntries(topParentOid, middleParentOid, childOid, map);
    }

    @Test
    public void testAclsRetrievalWithCustomBatchSize() throws Exception {
        ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        ObjectIdentity childOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102));

        // Set a batch size to allow multiple database queries in order to retrieve all acls
        ((BasicLookupStrategy) this.strategy).setBatchSize(1);
        Map map = this.strategy.readAclsById(new ObjectIdentity[] { topParentOid, middleParentOid, childOid }, null);
        checkEntries(topParentOid, middleParentOid, childOid, map);
    }

    private void checkEntries(ObjectIdentity topParentOid, ObjectIdentity middleParentOid, ObjectIdentity childOid, Map map)
            throws Exception {
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
        Assert.assertEquals(2, topParent.getEntries().length);
        Assert.assertEquals(1, middleParent.getEntries().length);
        Assert.assertEquals(1, child.getEntries().length);

        // Check object identities were correctly retrieved
        Assert.assertEquals(topParentOid, topParent.getObjectIdentity());
        Assert.assertEquals(middleParentOid, middleParent.getObjectIdentity());
        Assert.assertEquals(childOid, child.getObjectIdentity());

        // Check each entry
        Assert.assertTrue(topParent.isEntriesInheriting());
        Assert.assertEquals(topParent.getId(), new Long(1));
        Assert.assertEquals(topParent.getOwner(), new PrincipalSid("ben"));
        Assert.assertEquals(topParent.getEntries()[0].getId(), new Long(1));
        Assert.assertEquals(topParent.getEntries()[0].getPermission(), BasePermission.READ);
        Assert.assertEquals(topParent.getEntries()[0].getSid(), new PrincipalSid("ben"));
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries()[0]).isAuditFailure());
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries()[0]).isAuditSuccess());
        Assert.assertTrue(((AuditableAccessControlEntry) topParent.getEntries()[0]).isGranting());

        Assert.assertEquals(topParent.getEntries()[1].getId(), new Long(2));
        Assert.assertEquals(topParent.getEntries()[1].getPermission(), BasePermission.WRITE);
        Assert.assertEquals(topParent.getEntries()[1].getSid(), new PrincipalSid("ben"));
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries()[1]).isAuditFailure());
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries()[1]).isAuditSuccess());
        Assert.assertFalse(((AuditableAccessControlEntry) topParent.getEntries()[1]).isGranting());

        Assert.assertTrue(middleParent.isEntriesInheriting());
        Assert.assertEquals(middleParent.getId(), new Long(2));
        Assert.assertEquals(middleParent.getOwner(), new PrincipalSid("ben"));
        Assert.assertEquals(middleParent.getEntries()[0].getId(), new Long(3));
        Assert.assertEquals(middleParent.getEntries()[0].getPermission(), BasePermission.DELETE);
        Assert.assertEquals(middleParent.getEntries()[0].getSid(), new PrincipalSid("ben"));
        Assert.assertFalse(((AuditableAccessControlEntry) middleParent.getEntries()[0]).isAuditFailure());
        Assert.assertFalse(((AuditableAccessControlEntry) middleParent.getEntries()[0]).isAuditSuccess());
        Assert.assertTrue(((AuditableAccessControlEntry) middleParent.getEntries()[0]).isGranting());

        Assert.assertTrue(child.isEntriesInheriting());
        Assert.assertEquals(child.getId(), new Long(3));
        Assert.assertEquals(child.getOwner(), new PrincipalSid("ben"));
        Assert.assertEquals(child.getEntries()[0].getId(), new Long(4));
        Assert.assertEquals(child.getEntries()[0].getPermission(), BasePermission.DELETE);
        Assert.assertEquals(child.getEntries()[0].getSid(), new PrincipalSid("ben"));
        Assert.assertFalse(((AuditableAccessControlEntry) child.getEntries()[0]).isAuditFailure());
        Assert.assertFalse(((AuditableAccessControlEntry) child.getEntries()[0]).isAuditSuccess());
        Assert.assertFalse(((AuditableAccessControlEntry) child.getEntries()[0]).isGranting());
    }
}