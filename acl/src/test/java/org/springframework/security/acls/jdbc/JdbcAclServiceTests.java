/*
 * Copyright 2002-2018 the original author or authors.
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

import javax.sql.DataSource;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * Unit and Integration tests the ACL JdbcAclService using an in-memory database.
 *
 * @author Nena Raab
 */
@RunWith(MockitoJUnitRunner.class)
public class JdbcAclServiceTests {

	private EmbeddedDatabase embeddedDatabase;

	@Mock
	private DataSource dataSource;

	@Mock
	private LookupStrategy lookupStrategy;

	@Mock
	JdbcOperations jdbcOperations;

	private JdbcAclService aclServiceIntegration;

	private JdbcAclService aclService;

	@Before
	public void setUp() {
		aclService = new JdbcAclService(jdbcOperations, lookupStrategy);
		aclServiceIntegration = new JdbcAclService(embeddedDatabase, lookupStrategy);
	}

	@Before
	public void setUpEmbeddedDatabase() {
		embeddedDatabase = new EmbeddedDatabaseBuilder()//
				.addScript("createAclSchemaWithAclClassIdType.sql").addScript("db/sql/test_data_hierarchy.sql").build();
	}

	@After
	public void tearDownEmbeddedDatabase() {
		embeddedDatabase.shutdown();
	}

	// SEC-1898
	@Test(expected = NotFoundException.class)
	public void readAclByIdMissingAcl() {
		Map<ObjectIdentity, Acl> result = new HashMap<>();
		when(lookupStrategy.readAclsById(anyList(), anyList())).thenReturn(result);
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Object.class, 1);
		List<Sid> sids = Arrays.<Sid>asList(new PrincipalSid("user"));

		aclService.readAclById(objectIdentity, sids);
	}

	@Test
	public void findOneChildren() {
		List<ObjectIdentity> result = new ArrayList<>();
		result.add(new ObjectIdentityImpl(Object.class, "5577"));
		Object[] args = { "1", "org.springframework.security.acls.jdbc.JdbcAclServiceTests$MockLongIdDomainObject" };
		when(jdbcOperations.query(anyString(), aryEq(args), any(RowMapper.class))).thenReturn(result);
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(MockLongIdDomainObject.class, 1L);

		List<ObjectIdentity> objectIdentities = aclService.findChildren(objectIdentity);
		assertThat(objectIdentities.size()).isEqualTo(1);
		assertThat(objectIdentities.get(0).getIdentifier()).isEqualTo("5577");
	}

	@Test
	public void findNoChildren() {
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(MockLongIdDomainObject.class, 1L);

		List<ObjectIdentity> objectIdentities = aclService.findChildren(objectIdentity);
		assertThat(objectIdentities).isNull();
	}

	// ~ Some integration tests
	// ========================================================================================================

	@Test
	public void findChildrenWithoutIdType() {
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(MockLongIdDomainObject.class, 4711L);

		List<ObjectIdentity> objectIdentities = aclServiceIntegration.findChildren(objectIdentity);
		assertThat(objectIdentities.size()).isEqualTo(1);
		assertThat(objectIdentities.get(0).getType()).isEqualTo(MockUntypedIdDomainObject.class.getName());
		assertThat(objectIdentities.get(0).getIdentifier()).isEqualTo(5000L);
	}

	@Test
	public void findChildrenForUnknownObject() {
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(Object.class, 33);

		List<ObjectIdentity> objectIdentities = aclServiceIntegration.findChildren(objectIdentity);
		assertThat(objectIdentities).isNull();
	}

	@Test
	public void findChildrenOfIdTypeLong() {
		ObjectIdentity objectIdentity = new ObjectIdentityImpl("location", "US-PAL");

		List<ObjectIdentity> objectIdentities = aclServiceIntegration.findChildren(objectIdentity);
		assertThat(objectIdentities.size()).isEqualTo(2);
		assertThat(objectIdentities.get(0).getType()).isEqualTo(MockLongIdDomainObject.class.getName());
		assertThat(objectIdentities.get(0).getIdentifier()).isEqualTo(4711L);
		assertThat(objectIdentities.get(1).getType()).isEqualTo(MockLongIdDomainObject.class.getName());
		assertThat(objectIdentities.get(1).getIdentifier()).isEqualTo(4712L);
	}

	@Test
	public void findChildrenOfIdTypeString() {
		ObjectIdentity objectIdentity = new ObjectIdentityImpl("location", "US");

		aclServiceIntegration.setAclClassIdSupported(true);
		List<ObjectIdentity> objectIdentities = aclServiceIntegration.findChildren(objectIdentity);
		assertThat(objectIdentities.size()).isEqualTo(1);
		assertThat(objectIdentities.get(0).getType()).isEqualTo("location");
		assertThat(objectIdentities.get(0).getIdentifier()).isEqualTo("US-PAL");
	}

	@Test
	public void findChildrenOfIdTypeUUID() {
		ObjectIdentity objectIdentity = new ObjectIdentityImpl(MockUntypedIdDomainObject.class, 5000L);

		aclServiceIntegration.setAclClassIdSupported(true);
		List<ObjectIdentity> objectIdentities = aclServiceIntegration.findChildren(objectIdentity);
		assertThat(objectIdentities.size()).isEqualTo(1);
		assertThat(objectIdentities.get(0).getType()).isEqualTo("costcenter");
		assertThat(objectIdentities.get(0).getIdentifier())
				.isEqualTo(UUID.fromString("25d93b3f-c3aa-4814-9d5e-c7c96ced7762"));
	}

	private class MockLongIdDomainObject {

		private Object id;

		public Object getId() {
			return id;
		}

		public void setId(Object id) {
			this.id = id;
		}

	}

	private class MockUntypedIdDomainObject {

		private Object id;

		public Object getId() {
			return id;
		}

		public void setId(Object id) {
			this.id = id;
		}

	}

}
