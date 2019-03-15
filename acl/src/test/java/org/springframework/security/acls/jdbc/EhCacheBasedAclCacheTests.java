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

import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.List;

import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.FieldUtils;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests {@link EhCacheBasedAclCache}
 *
 * @author Andrei Stefan
 */
@RunWith(MockitoJUnitRunner.class)
public class EhCacheBasedAclCacheTests {
	private static final String TARGET_CLASS = "org.springframework.security.acls.TargetObject";

	@Mock
	private Ehcache cache;
	@Captor
	private ArgumentCaptor<Element> element;

	private EhCacheBasedAclCache myCache;

	private MutableAcl acl;

	@Before
	public void setup() {
		myCache = new EhCacheBasedAclCache(cache, new DefaultPermissionGrantingStrategy(
				new ConsoleAuditLogger()), new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_USER")));

		ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(100));
		AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority(
						"ROLE_AUDITING"), new SimpleGrantedAuthority("ROLE_GENERAL"));

		acl = new AclImpl(identity, Long.valueOf(1), aclAuthorizationStrategy,
				new ConsoleAuditLogger());
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorRejectsNullParameters() throws Exception {
		new EhCacheBasedAclCache(null, new DefaultPermissionGrantingStrategy(
				new ConsoleAuditLogger()), new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_USER")));
	}

	@Test
	public void methodsRejectNullParameters() throws Exception {
		try {
			Serializable id = null;
			myCache.evictFromCache(id);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			ObjectIdentity obj = null;
			myCache.evictFromCache(obj);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			Serializable id = null;
			myCache.getFromCache(id);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			ObjectIdentity obj = null;
			myCache.getFromCache(obj);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			MutableAcl acl = null;
			myCache.putInCache(acl);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	// SEC-527
	@Test
	public void testDiskSerializationOfMutableAclObjectInstance() throws Exception {
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

		assertThat(retrieved).isEqualTo(acl);

		Object retrieved1 = FieldUtils.getProtectedFieldValue("aclAuthorizationStrategy",
				retrieved);
		assertThat(retrieved1).isNull();

		Object retrieved2 = FieldUtils.getProtectedFieldValue(
				"permissionGrantingStrategy", retrieved);
		assertThat(retrieved2).isNull();
	}

	@Test
	public void clearCache() throws Exception {
		myCache.clearCache();

		verify(cache).removeAll();
	}

	@Test
	public void putInCache() throws Exception {
		myCache.putInCache(acl);

		verify(cache, times(2)).put(element.capture());
		assertThat(element.getValue().getKey()).isEqualTo(acl.getId());
		assertThat(element.getValue().getObjectValue()).isEqualTo(acl);
		assertThat(element.getAllValues().get(0).getKey()).isEqualTo(
				acl.getObjectIdentity());
		assertThat(element.getAllValues().get(0).getObjectValue()).isEqualTo(acl);
	}

	@Test
	public void putInCacheAclWithParent() throws Exception {
		Authentication auth = new TestingAuthenticationToken("user", "password",
				"ROLE_GENERAL");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);

		ObjectIdentity identityParent = new ObjectIdentityImpl(TARGET_CLASS,
				Long.valueOf(2));
		AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority(
						"ROLE_AUDITING"), new SimpleGrantedAuthority("ROLE_GENERAL"));
		MutableAcl parentAcl = new AclImpl(identityParent, Long.valueOf(2),
				aclAuthorizationStrategy, new ConsoleAuditLogger());
		acl.setParent(parentAcl);

		myCache.putInCache(acl);

		verify(cache, times(4)).put(element.capture());

		List<Element> allValues = element.getAllValues();

		assertThat(allValues.get(0).getKey()).isEqualTo(parentAcl.getObjectIdentity());
		assertThat(allValues.get(0).getObjectValue()).isEqualTo(parentAcl);

		assertThat(allValues.get(1).getKey()).isEqualTo(parentAcl.getId());
		assertThat(allValues.get(1).getObjectValue()).isEqualTo(parentAcl);

		assertThat(allValues.get(2).getKey()).isEqualTo(acl.getObjectIdentity());
		assertThat(allValues.get(2).getObjectValue()).isEqualTo(acl);

		assertThat(allValues.get(3).getKey()).isEqualTo(acl.getId());
		assertThat(allValues.get(3).getObjectValue()).isEqualTo(acl);
	}

	@Test
	public void getFromCacheSerializable() throws Exception {
		when(cache.get(acl.getId())).thenReturn(new Element(acl.getId(), acl));

		assertThat(myCache.getFromCache(acl.getId())).isEqualTo(acl);
	}

	@Test
	public void getFromCacheSerializablePopulatesTransient() throws Exception {
		when(cache.get(acl.getId())).thenReturn(new Element(acl.getId(), acl));

		myCache.putInCache(acl);

		ReflectionTestUtils.setField(acl, "permissionGrantingStrategy", null);
		ReflectionTestUtils.setField(acl, "aclAuthorizationStrategy", null);

		MutableAcl fromCache = myCache.getFromCache(acl.getId());

		assertThat(ReflectionTestUtils.getField(fromCache, "aclAuthorizationStrategy"))
				.isNotNull();
		assertThat(ReflectionTestUtils.getField(fromCache, "permissionGrantingStrategy"))
				.isNotNull();
	}

	@Test
	public void getFromCacheObjectIdentity() throws Exception {
		when(cache.get(acl.getId())).thenReturn(new Element(acl.getId(), acl));

		assertThat(myCache.getFromCache(acl.getId())).isEqualTo(acl);
	}

	@Test
	public void getFromCacheObjectIdentityPopulatesTransient() throws Exception {
		when(cache.get(acl.getObjectIdentity()))
				.thenReturn(new Element(acl.getId(), acl));

		myCache.putInCache(acl);

		ReflectionTestUtils.setField(acl, "permissionGrantingStrategy", null);
		ReflectionTestUtils.setField(acl, "aclAuthorizationStrategy", null);

		MutableAcl fromCache = myCache.getFromCache(acl.getObjectIdentity());

		assertThat(ReflectionTestUtils.getField(fromCache, "aclAuthorizationStrategy"))
				.isNotNull();
		assertThat(ReflectionTestUtils.getField(fromCache, "permissionGrantingStrategy"))
				.isNotNull();
	}

	@Test
	public void evictCacheSerializable() throws Exception {
		when(cache.get(acl.getObjectIdentity()))
				.thenReturn(new Element(acl.getId(), acl));

		myCache.evictFromCache(acl.getObjectIdentity());

		verify(cache).remove(acl.getId());
		verify(cache).remove(acl.getObjectIdentity());
	}

	@Test
	public void evictCacheObjectIdentity() throws Exception {
		when(cache.get(acl.getId())).thenReturn(new Element(acl.getId(), acl));

		myCache.evictFromCache(acl.getId());

		verify(cache).remove(acl.getId());
		verify(cache).remove(acl.getObjectIdentity());
	}
}
