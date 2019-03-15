/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls.jdbc;

import static org.assertj.core.api.Assertions.*;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import org.junit.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.FileCopyUtils;

import java.util.*;

/**
 * Tests {@link BasicLookupStrategy}
 *
 * @author Andrei Stefan
 */
public class BasicLookupStrategyTests {

	private static final Sid BEN_SID = new PrincipalSid("ben");
	private static final String TARGET_CLASS = "org.springframework.security.acls.TargetObject";

	// ~ Instance fields
	// ================================================================================================

	private static JdbcTemplate jdbcTemplate;
	private BasicLookupStrategy strategy;
	private static SingleConnectionDataSource dataSource;
	private static CacheManager cacheManager;

	// ~ Methods
	// ========================================================================================================
	@BeforeClass
	public static void initCacheManaer() {
		cacheManager = CacheManager.create();
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
		EhCacheBasedAclCache cache = new EhCacheBasedAclCache(getCache(),
				new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()),
				new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_USER")));
		AclAuthorizationStrategy authorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"));
		strategy = new BasicLookupStrategy(dataSource, cache, authorizationStrategy,
				new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()));
		strategy.setPermissionFactory(new DefaultPermissionFactory());
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
		// Deliberately use an integer for the child, to reproduce bug report in
		// SEC-819
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, Integer.valueOf(102));

		Map<ObjectIdentity, Acl> map = this.strategy
				.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);
		checkEntries(topParentOid, middleParentOid, childOid, map);
	}

	@Test
	public void testAclsRetrievalFromCacheOnly() throws Exception {
		ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, Integer.valueOf(100));
		ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(101));
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(102));

		// Objects were put in cache
		strategy.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);

		// Let's empty the database to force acls retrieval from cache
		emptyDatabase();
		Map<ObjectIdentity, Acl> map = this.strategy
				.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);

		checkEntries(topParentOid, middleParentOid, childOid, map);
	}

	@Test
	public void testAclsRetrievalWithCustomBatchSize() throws Exception {
		ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(100));
		ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, Integer.valueOf(101));
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, new Long(102));

		// Set a batch size to allow multiple database queries in order to
		// retrieve all
		// acls
		this.strategy.setBatchSize(1);
		Map<ObjectIdentity, Acl> map = this.strategy
				.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);
		checkEntries(topParentOid, middleParentOid, childOid, map);
	}

	private void checkEntries(ObjectIdentity topParentOid, ObjectIdentity middleParentOid, ObjectIdentity childOid,
			Map<ObjectIdentity, Acl> map) throws Exception {
		assertThat(map).hasSize(3);

		MutableAcl topParent = (MutableAcl) map.get(topParentOid);
		MutableAcl middleParent = (MutableAcl) map.get(middleParentOid);
		MutableAcl child = (MutableAcl) map.get(childOid);

		// Check the retrieved versions has IDs
		assertThat(topParent.getId()).isNotNull();
		assertThat(middleParent.getId()).isNotNull();
		assertThat(child.getId()).isNotNull();

		// Check their parents were correctly retrieved
		assertThat(topParent.getParentAcl()).isNull();
		assertThat(middleParent.getParentAcl().getObjectIdentity()).isEqualTo(topParentOid);
		assertThat(child.getParentAcl().getObjectIdentity()).isEqualTo(middleParentOid);

		// Check their ACEs were correctly retrieved
		assertThat(topParent.getEntries()).hasSize(2);
		assertThat(middleParent.getEntries()).hasSize(1);
		assertThat(child.getEntries()).hasSize(1);

		// Check object identities were correctly retrieved
		assertThat(topParent.getObjectIdentity()).isEqualTo(topParentOid);
		assertThat(middleParent.getObjectIdentity()).isEqualTo(middleParentOid);
		assertThat(child.getObjectIdentity()).isEqualTo(childOid);

		// Check each entry
		assertThat(topParent.isEntriesInheriting()).isTrue();
		assertThat(Long.valueOf(1)).isEqualTo(topParent.getId());
		assertThat(new PrincipalSid("ben")).isEqualTo(topParent.getOwner());
		assertThat(Long.valueOf(1)).isEqualTo(topParent.getEntries().get(0).getId());
		assertThat(topParent.getEntries().get(0).getPermission()).isEqualTo(BasePermission.READ);
		assertThat(topParent.getEntries().get(0).getSid()).isEqualTo(new PrincipalSid("ben"));
		assertThat(((AuditableAccessControlEntry) topParent.getEntries().get(0)).isAuditFailure()).isFalse();
		assertThat(((AuditableAccessControlEntry) topParent.getEntries().get(0)).isAuditSuccess()).isFalse();
		assertThat((topParent.getEntries().get(0)).isGranting()).isTrue();

		assertThat(Long.valueOf(2)).isEqualTo(topParent.getEntries().get(1).getId());
		assertThat(topParent.getEntries().get(1).getPermission()).isEqualTo(BasePermission.WRITE);
		assertThat(topParent.getEntries().get(1).getSid()).isEqualTo(new PrincipalSid("ben"));
		assertThat(((AuditableAccessControlEntry) topParent.getEntries().get(1)).isAuditFailure()).isFalse();
		assertThat(((AuditableAccessControlEntry) topParent.getEntries().get(1)).isAuditSuccess()).isFalse();
		assertThat(topParent.getEntries().get(1).isGranting()).isFalse();

		assertThat(middleParent.isEntriesInheriting()).isTrue();
		assertThat(Long.valueOf(2)).isEqualTo(middleParent.getId());
		assertThat(new PrincipalSid("ben")).isEqualTo(middleParent.getOwner());
		assertThat(Long.valueOf(3)).isEqualTo(middleParent.getEntries().get(0).getId());
		assertThat(middleParent.getEntries().get(0).getPermission()).isEqualTo(BasePermission.DELETE);
		assertThat(middleParent.getEntries().get(0).getSid()).isEqualTo(new PrincipalSid("ben"));
		assertThat(((AuditableAccessControlEntry) middleParent.getEntries().get(0)).isAuditFailure()).isFalse();
		assertThat(((AuditableAccessControlEntry) middleParent.getEntries().get(0)).isAuditSuccess()).isFalse();
		assertThat(middleParent.getEntries().get(0).isGranting()).isTrue();

		assertThat(child.isEntriesInheriting()).isTrue();
		assertThat(Long.valueOf(3)).isEqualTo(child.getId());
		assertThat(new PrincipalSid("ben")).isEqualTo(child.getOwner());
		assertThat(Long.valueOf(4)).isEqualTo(child.getEntries().get(0).getId());
		assertThat(child.getEntries().get(0).getPermission()).isEqualTo(BasePermission.DELETE);
		assertThat(new PrincipalSid("ben")).isEqualTo(child.getEntries().get(0).getSid());
		assertThat(((AuditableAccessControlEntry) child.getEntries().get(0)).isAuditFailure()).isFalse();
		assertThat(((AuditableAccessControlEntry) child.getEntries().get(0)).isAuditSuccess()).isFalse();
		assertThat((child.getEntries().get(0)).isGranting()).isFalse();
	}

	@Test
	public void testAllParentsAreRetrievedWhenChildIsLoaded() throws Exception {
		String query = "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (4,2,103,1,1,1);";
		jdbcTemplate.execute(query);

		ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(100));
		ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(101));
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(102));
		ObjectIdentity middleParent2Oid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(103));

		// Retrieve the child
		Map<ObjectIdentity, Acl> map = this.strategy.readAclsById(Arrays.asList(childOid), null);

		// Check that the child and all its parents were retrieved
		assertThat(map.get(childOid)).isNotNull();
		assertThat(map.get(childOid).getObjectIdentity()).isEqualTo(childOid);
		assertThat(map.get(middleParentOid)).isNotNull();
		assertThat(map.get(middleParentOid).getObjectIdentity()).isEqualTo(middleParentOid);
		assertThat(map.get(topParentOid)).isNotNull();
		assertThat(map.get(topParentOid).getObjectIdentity()).isEqualTo(topParentOid);

		// The second parent shouldn't have been retrieved
		assertThat(map.get(middleParent2Oid)).isNull();
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
		ObjectIdentity parent2Oid = new ObjectIdentityImpl(TARGET_CLASS, Integer.valueOf(106));
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, Integer.valueOf(107));

		// First lookup only child, thus populating the cache with grandParent,
		// parent1
		// and child
		List<Permission> checkPermission = Arrays.asList(BasePermission.READ);
		List<Sid> sids = Arrays.asList(BEN_SID);
		List<ObjectIdentity> childOids = Arrays.asList(childOid);

		strategy.setBatchSize(6);
		Map<ObjectIdentity, Acl> foundAcls = strategy.readAclsById(childOids, sids);

		Acl foundChildAcl = foundAcls.get(childOid);
		assertThat(foundChildAcl).isNotNull();
		assertThat(foundChildAcl.isGranted(checkPermission, sids, false)).isTrue();

		// Search for object identities has to be done in the following order:
		// last
		// element have to be one which
		// is already in cache and the element before it must not be stored in
		// cache
		List<ObjectIdentity> allOids = Arrays.asList(grandParentOid, parent1Oid, parent2Oid, childOid);
		try {
			foundAcls = strategy.readAclsById(allOids, sids);

		} catch (NotFoundException notExpected) {
			fail("It shouldn't have thrown NotFoundException");
		}

		Acl foundParent2Acl = foundAcls.get(parent2Oid);
		assertThat(foundParent2Acl).isNotNull();
		assertThat(foundParent2Acl.isGranted(checkPermission, sids, false)).isTrue();
	}

	@Test(expected = IllegalArgumentException.class)
	public void nullOwnerIsNotSupported() {
		String query = "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (4,2,104,null,null,1);";

		jdbcTemplate.execute(query);

		ObjectIdentity oid = new ObjectIdentityImpl(TARGET_CLASS, new Long(104));

		strategy.readAclsById(Arrays.asList(oid), Arrays.asList(BEN_SID));
	}

	@Test
	public void testCreatePrincipalSid() {
		Sid result = strategy.createSid(true, "sid");

		assertThat(result.getClass()).isEqualTo(PrincipalSid.class);
		assertThat(((PrincipalSid) result).getPrincipal()).isEqualTo("sid");
	}

	@Test
	public void testCreateGrantedAuthority() {
		Sid result = strategy.createSid(false, "sid");

		assertThat(result.getClass()).isEqualTo(GrantedAuthoritySid.class);
		assertThat(((GrantedAuthoritySid) result).getGrantedAuthority()).isEqualTo("sid");
	}

}
