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
import java.util.Map;

import javax.sql.DataSource;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.core.convert.ConversionFailedException;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.ObjectIdentity;

import junit.framework.Assert;

/**
 * Tests {@link BasicLookupStrategy} with Acl Class type id set to UUID.
 *
 * @author Paul Wheeler
 */
public class BasicLookupStrategyWithAclClassTypeTests extends AbstractBasicLookupStrategyTests {

	private static final BasicLookupStrategyTestsDbHelper DATABASE_HELPER = new BasicLookupStrategyTestsDbHelper(true);

	private BasicLookupStrategy uuidEnabledStrategy;

	@Override
	public JdbcTemplate getJdbcTemplate() {
		return DATABASE_HELPER.getJdbcTemplate();
	}

	@Override
	public DataSource getDataSource() {
		return DATABASE_HELPER.getDataSource();
	}

	@BeforeClass
	public static void createDatabase() throws Exception {
		DATABASE_HELPER.createDatabase();
	}

	@AfterClass
	public static void dropDatabase() {
		DATABASE_HELPER.getDataSource().destroy();
	}

	@Before
	public void initializeBeans() {
		super.initializeBeans();
		uuidEnabledStrategy = new BasicLookupStrategy(getDataSource(), aclCache(), aclAuthStrategy(),
				new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()));
		uuidEnabledStrategy.setPermissionFactory(new DefaultPermissionFactory());
		uuidEnabledStrategy.setAclClassIdSupported(true);
		uuidEnabledStrategy.setConversionService(new DefaultConversionService());
	}

	@Before
	public void populateDatabaseForAclClassTypeTests() {
		String query = "INSERT INTO acl_class(ID,CLASS,CLASS_ID_TYPE) VALUES (3,'" + TARGET_CLASS_WITH_UUID
				+ "', 'java.util.UUID');"
				+ "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (4,3,'"
				+ OBJECT_IDENTITY_UUID.toString() + "',null,1,1);"
				+ "INSERT INTO acl_object_identity(ID,OBJECT_ID_CLASS,OBJECT_ID_IDENTITY,PARENT_OBJECT,OWNER_SID,ENTRIES_INHERITING) VALUES (5,3,'"
				+ OBJECT_IDENTITY_LONG_AS_UUID + "',null,1,1);"
				+ "INSERT INTO acl_entry(ID,ACL_OBJECT_IDENTITY,ACE_ORDER,SID,MASK,GRANTING,AUDIT_SUCCESS,AUDIT_FAILURE) VALUES (5,4,0,1,8,0,0,0);"
				+ "INSERT INTO acl_entry(ID,ACL_OBJECT_IDENTITY,ACE_ORDER,SID,MASK,GRANTING,AUDIT_SUCCESS,AUDIT_FAILURE) VALUES (6,5,0,1,8,0,0,0);";
		DATABASE_HELPER.getJdbcTemplate().execute(query);
	}

	@Test
	public void testReadObjectIdentityUsingUuidType() {
		ObjectIdentity oid = new ObjectIdentityImpl(TARGET_CLASS_WITH_UUID, OBJECT_IDENTITY_UUID);
		Map<ObjectIdentity, Acl> foundAcls = uuidEnabledStrategy.readAclsById(Arrays.asList(oid),
				Arrays.asList(BEN_SID));
		Assert.assertEquals(1, foundAcls.size());
		Assert.assertNotNull(foundAcls.get(oid));
	}

	@Test
	public void testReadObjectIdentityUsingLongTypeWithConversionServiceEnabled() {
		ObjectIdentity oid = new ObjectIdentityImpl(TARGET_CLASS, 100L);
		Map<ObjectIdentity, Acl> foundAcls = uuidEnabledStrategy.readAclsById(Arrays.asList(oid),
				Arrays.asList(BEN_SID));
		Assert.assertEquals(1, foundAcls.size());
		Assert.assertNotNull(foundAcls.get(oid));
	}

	@Test(expected = ConversionFailedException.class)
	public void testReadObjectIdentityUsingNonUuidInDatabase() {
		ObjectIdentity oid = new ObjectIdentityImpl(TARGET_CLASS_WITH_UUID, OBJECT_IDENTITY_LONG_AS_UUID);
		uuidEnabledStrategy.readAclsById(Arrays.asList(oid), Arrays.asList(BEN_SID));
	}

}
