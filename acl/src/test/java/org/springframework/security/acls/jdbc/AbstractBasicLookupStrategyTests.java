/*
 * Copyright 2002-2017 the original author or authors.
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

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.sql.DataSource;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.acls.TargetObject;
import org.springframework.security.acls.TargetObjectWithUUID;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link BasicLookupStrategy}
 *
 * @author Andrei Stefan
 */
public abstract class AbstractBasicLookupStrategyTests {

	protected static final Sid BEN_SID = new PrincipalSid("ben");

	protected static final String TARGET_CLASS = TargetObject.class.getName();

	protected static final String TARGET_CLASS_WITH_UUID = TargetObjectWithUUID.class.getName();

	protected static final UUID OBJECT_IDENTITY_UUID = UUID.randomUUID();

	protected static final Long OBJECT_IDENTITY_LONG_AS_UUID = 110L;

	private BasicLookupStrategy strategy;

	private static CacheManager cacheManager;

	public abstract JdbcTemplate getJdbcTemplate();

	public abstract DataSource getDataSource();

	@BeforeClass
	public static void initCacheManaer() {
		cacheManager = CacheManager.create();
		cacheManager.addCache(new Cache("basiclookuptestcache", 500, false, false, 30, 30));
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
		getJdbcTemplate().execute(query);
	}

	@Before
	public void initializeBeans() {
		this.strategy = new BasicLookupStrategy(getDataSource(), aclCache(), aclAuthStrategy(),
				new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()));
		this.strategy.setPermissionFactory(new DefaultPermissionFactory());
	}

	protected AclAuthorizationStrategy aclAuthStrategy() {
		return new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"));
	}

	protected EhCacheBasedAclCache aclCache() {
		return new EhCacheBasedAclCache(getCache(), new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()),
				new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_USER")));
	}

	@After
	public void emptyDatabase() {
		String query = "DELETE FROM acl_entry;" + "DELETE FROM acl_object_identity WHERE ID = 9;"
				+ "DELETE FROM acl_object_identity WHERE ID = 8;" + "DELETE FROM acl_object_identity WHERE ID = 7;"
				+ "DELETE FROM acl_object_identity WHERE ID = 6;" + "DELETE FROM acl_object_identity WHERE ID = 5;"
				+ "DELETE FROM acl_object_identity WHERE ID = 4;" + "DELETE FROM acl_object_identity WHERE ID = 3;"
				+ "DELETE FROM acl_object_identity WHERE ID = 2;" + "DELETE FROM acl_object_identity WHERE ID = 1;"
				+ "DELETE FROM acl_class;" + "DELETE FROM acl_sid;";
		getJdbcTemplate().execute(query);
	}

	protected Ehcache getCache() {
		Ehcache cache = cacheManager.getCache("basiclookuptestcache");
		cache.removeAll();
		return cache;
	}

	@Test
	public void testAclsRetrievalWithDefaultBatchSize() throws Exception {
		ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, 100L);
		ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, 101L);
		// Deliberately use an integer for the child, to reproduce bug report in SEC-819
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, 102);

		Map<ObjectIdentity, Acl> map = this.strategy
				.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);
		checkEntries(topParentOid, middleParentOid, childOid, map);
	}

	@Test
	public void testAclsRetrievalFromCacheOnly() throws Exception {
		ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, 100);
		ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, 101L);
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, 102L);

		// Objects were put in cache
		this.strategy.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);

		// Let's empty the database to force acls retrieval from cache
		emptyDatabase();
		Map<ObjectIdentity, Acl> map = this.strategy
				.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);

		checkEntries(topParentOid, middleParentOid, childOid, map);
	}

	@Test
	public void testAclsRetrievalWithCustomBatchSize() throws Exception {
		ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, 100L);
		ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, 101);
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, 102L);

		// Set a batch size to allow multiple database queries in order to retrieve all
		// acls
		this.strategy.setBatchSize(1);
		Map<ObjectIdentity, Acl> map = this.strategy
				.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid), null);
		checkEntries(topParentOid, middleParentOid, childOid, map);
	}

	private void checkEntries(ObjectIdentity topParentOid, ObjectIdentity middleParentOid, ObjectIdentity childOid,
			Map<ObjectIdentity, Acl> map) {
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
	public void testAllParentsAreRetrievedWhenChildIsLoaded() {
		String query = "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (6,2,103,1,1,1);";
		getJdbcTemplate().execute(query);

		ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, 100L);
		ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, 101L);
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, 102L);
		ObjectIdentity middleParent2Oid = new ObjectIdentityImpl(TARGET_CLASS, 103L);

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
	public void testReadAllObjectIdentitiesWhenLastElementIsAlreadyCached() {
		String query = "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (6,2,105,null,1,1);"
				+ "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (7,2,106,6,1,1);"
				+ "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (8,2,107,6,1,1);"
				+ "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (9,2,108,7,1,1);"
				+ "INSERT INTO acl_entry(ID,ACL_OBJECT_IDENTITY,ACE_ORDER,SID,MASK,GRANTING,AUDIT_SUCCESS,AUDIT_FAILURE) VALUES (7,6,0,1,1,1,0,0)";
		getJdbcTemplate().execute(query);

		ObjectIdentity grandParentOid = new ObjectIdentityImpl(TARGET_CLASS, 104L);
		ObjectIdentity parent1Oid = new ObjectIdentityImpl(TARGET_CLASS, 105L);
		ObjectIdentity parent2Oid = new ObjectIdentityImpl(TARGET_CLASS, 106);
		ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, 107);

		// First lookup only child, thus populating the cache with grandParent,
		// parent1
		// and child
		List<Permission> checkPermission = Arrays.asList(BasePermission.READ);
		List<Sid> sids = Arrays.asList(BEN_SID);
		List<ObjectIdentity> childOids = Arrays.asList(childOid);

		this.strategy.setBatchSize(6);
		Map<ObjectIdentity, Acl> foundAcls = this.strategy.readAclsById(childOids, sids);

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
			foundAcls = this.strategy.readAclsById(allOids, sids);

		}
		catch (NotFoundException notExpected) {
			fail("It shouldn't have thrown NotFoundException");
		}

		Acl foundParent2Acl = foundAcls.get(parent2Oid);
		assertThat(foundParent2Acl).isNotNull();
		assertThat(foundParent2Acl.isGranted(checkPermission, sids, false)).isTrue();
	}

	@Test(expected = IllegalArgumentException.class)
	public void nullOwnerIsNotSupported() {
		String query = "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (6,2,104,null,null,1);";

		getJdbcTemplate().execute(query);

		ObjectIdentity oid = new ObjectIdentityImpl(TARGET_CLASS, 104L);

		this.strategy.readAclsById(Arrays.asList(oid), Arrays.asList(BEN_SID));
	}

	@Test
	public void testCreatePrincipalSid() {
		Sid result = this.strategy.createSid(true, "sid");

		assertThat(result.getClass()).isEqualTo(PrincipalSid.class);
		assertThat(((PrincipalSid) result).getPrincipal()).isEqualTo("sid");
	}

	@Test
	public void testCreateGrantedAuthority() {
		Sid result = this.strategy.createSid(false, "sid");

		assertThat(result.getClass()).isEqualTo(GrantedAuthoritySid.class);
		assertThat(((GrantedAuthoritySid) result).getGrantedAuthority()).isEqualTo("sid");
	}

}
