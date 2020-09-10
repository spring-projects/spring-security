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

import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.FieldUtils;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

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
		this.myCache = new EhCacheBasedAclCache(this.cache,
				new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()),
				new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_USER")));
		ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, 100L);
		AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority("ROLE_AUDITING"),
				new SimpleGrantedAuthority("ROLE_GENERAL"));
		this.acl = new AclImpl(identity, 1L, aclAuthorizationStrategy, new ConsoleAuditLogger());
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorRejectsNullParameters() {
		new EhCacheBasedAclCache(null, new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()),
				new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_USER")));
	}

	@Test
	public void methodsRejectNullParameters() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.myCache.evictFromCache((Serializable) null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.myCache.evictFromCache((ObjectIdentity) null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.myCache.getFromCache((Serializable) null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.myCache.getFromCache((ObjectIdentity) null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.myCache.putInCache(null));
	}

	// SEC-527
	@Test
	public void testDiskSerializationOfMutableAclObjectInstance() throws Exception {
		// Serialization test
		File file = File.createTempFile("SEC_TEST", ".object");
		FileOutputStream fos = new FileOutputStream(file);
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(this.acl);
		oos.close();
		FileInputStream fis = new FileInputStream(file);
		ObjectInputStream ois = new ObjectInputStream(fis);
		MutableAcl retrieved = (MutableAcl) ois.readObject();
		ois.close();
		assertThat(retrieved).isEqualTo(this.acl);
		Object retrieved1 = FieldUtils.getProtectedFieldValue("aclAuthorizationStrategy", retrieved);
		assertThat(retrieved1).isNull();
		Object retrieved2 = FieldUtils.getProtectedFieldValue("permissionGrantingStrategy", retrieved);
		assertThat(retrieved2).isNull();
	}

	@Test
	public void clearCache() {
		this.myCache.clearCache();
		verify(this.cache).removeAll();
	}

	@Test
	public void putInCache() {
		this.myCache.putInCache(this.acl);
		verify(this.cache, times(2)).put(this.element.capture());
		assertThat(this.element.getValue().getKey()).isEqualTo(this.acl.getId());
		assertThat(this.element.getValue().getObjectValue()).isEqualTo(this.acl);
		assertThat(this.element.getAllValues().get(0).getKey()).isEqualTo(this.acl.getObjectIdentity());
		assertThat(this.element.getAllValues().get(0).getObjectValue()).isEqualTo(this.acl);
	}

	@Test
	public void putInCacheAclWithParent() {
		Authentication auth = new TestingAuthenticationToken("user", "password", "ROLE_GENERAL");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);
		ObjectIdentity identityParent = new ObjectIdentityImpl(TARGET_CLASS, 2L);
		AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority("ROLE_AUDITING"),
				new SimpleGrantedAuthority("ROLE_GENERAL"));
		MutableAcl parentAcl = new AclImpl(identityParent, 2L, aclAuthorizationStrategy, new ConsoleAuditLogger());
		this.acl.setParent(parentAcl);
		this.myCache.putInCache(this.acl);
		verify(this.cache, times(4)).put(this.element.capture());
		List<Element> allValues = this.element.getAllValues();
		assertThat(allValues.get(0).getKey()).isEqualTo(parentAcl.getObjectIdentity());
		assertThat(allValues.get(0).getObjectValue()).isEqualTo(parentAcl);
		assertThat(allValues.get(1).getKey()).isEqualTo(parentAcl.getId());
		assertThat(allValues.get(1).getObjectValue()).isEqualTo(parentAcl);
		assertThat(allValues.get(2).getKey()).isEqualTo(this.acl.getObjectIdentity());
		assertThat(allValues.get(2).getObjectValue()).isEqualTo(this.acl);
		assertThat(allValues.get(3).getKey()).isEqualTo(this.acl.getId());
		assertThat(allValues.get(3).getObjectValue()).isEqualTo(this.acl);
	}

	@Test
	public void getFromCacheSerializable() {
		given(this.cache.get(this.acl.getId())).willReturn(new Element(this.acl.getId(), this.acl));
		assertThat(this.myCache.getFromCache(this.acl.getId())).isEqualTo(this.acl);
	}

	@Test
	public void getFromCacheSerializablePopulatesTransient() {
		given(this.cache.get(this.acl.getId())).willReturn(new Element(this.acl.getId(), this.acl));
		this.myCache.putInCache(this.acl);
		ReflectionTestUtils.setField(this.acl, "permissionGrantingStrategy", null);
		ReflectionTestUtils.setField(this.acl, "aclAuthorizationStrategy", null);
		MutableAcl fromCache = this.myCache.getFromCache(this.acl.getId());
		assertThat(ReflectionTestUtils.getField(fromCache, "aclAuthorizationStrategy")).isNotNull();
		assertThat(ReflectionTestUtils.getField(fromCache, "permissionGrantingStrategy")).isNotNull();
	}

	@Test
	public void getFromCacheObjectIdentity() {
		given(this.cache.get(this.acl.getId())).willReturn(new Element(this.acl.getId(), this.acl));
		assertThat(this.myCache.getFromCache(this.acl.getId())).isEqualTo(this.acl);
	}

	@Test
	public void getFromCacheObjectIdentityPopulatesTransient() {
		given(this.cache.get(this.acl.getObjectIdentity())).willReturn(new Element(this.acl.getId(), this.acl));
		this.myCache.putInCache(this.acl);
		ReflectionTestUtils.setField(this.acl, "permissionGrantingStrategy", null);
		ReflectionTestUtils.setField(this.acl, "aclAuthorizationStrategy", null);
		MutableAcl fromCache = this.myCache.getFromCache(this.acl.getObjectIdentity());
		assertThat(ReflectionTestUtils.getField(fromCache, "aclAuthorizationStrategy")).isNotNull();
		assertThat(ReflectionTestUtils.getField(fromCache, "permissionGrantingStrategy")).isNotNull();
	}

	@Test
	public void evictCacheSerializable() {
		given(this.cache.get(this.acl.getObjectIdentity())).willReturn(new Element(this.acl.getId(), this.acl));
		this.myCache.evictFromCache(this.acl.getObjectIdentity());
		verify(this.cache).remove(this.acl.getId());
		verify(this.cache).remove(this.acl.getObjectIdentity());
	}

	@Test
	public void evictCacheObjectIdentity() {
		given(this.cache.get(this.acl.getId())).willReturn(new Element(this.acl.getId(), this.acl));
		this.myCache.evictFromCache(this.acl.getId());
		verify(this.cache).remove(this.acl.getId());
		verify(this.cache).remove(this.acl.getObjectIdentity());
	}

}
