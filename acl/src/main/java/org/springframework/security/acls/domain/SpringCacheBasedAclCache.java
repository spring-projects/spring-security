/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.acls.domain;

import java.io.Serializable;

import org.springframework.cache.Cache;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.util.FieldUtils;
import org.springframework.util.Assert;

/**
 * Simple implementation of {@link org.springframework.security.acls.model.AclCache} that
 * delegates to {@link Cache} implementation.
 * <p>
 * Designed to handle the transient fields in
 * {@link org.springframework.security.acls.domain.AclImpl}. Note that this implementation
 * assumes all {@link org.springframework.security.acls.domain.AclImpl} instances share
 * the same {@link org.springframework.security.acls.model.PermissionGrantingStrategy} and
 * {@link org.springframework.security.acls.domain.AclAuthorizationStrategy} instances.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class SpringCacheBasedAclCache implements AclCache {

	private final Cache cache;

	private PermissionGrantingStrategy permissionGrantingStrategy;

	private AclAuthorizationStrategy aclAuthorizationStrategy;

	public SpringCacheBasedAclCache(Cache cache, PermissionGrantingStrategy permissionGrantingStrategy,
			AclAuthorizationStrategy aclAuthorizationStrategy) {
		Assert.notNull(cache, "Cache required");
		Assert.notNull(permissionGrantingStrategy, "PermissionGrantingStrategy required");
		Assert.notNull(aclAuthorizationStrategy, "AclAuthorizationStrategy required");
		this.cache = cache;
		this.permissionGrantingStrategy = permissionGrantingStrategy;
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
	}

	@Override
	public void evictFromCache(Serializable pk) {
		Assert.notNull(pk, "Primary key (identifier) required");

		MutableAcl acl = getFromCache(pk);

		if (acl != null) {
			this.cache.evict(acl.getId());
			this.cache.evict(acl.getObjectIdentity());
		}
	}

	@Override
	public void evictFromCache(ObjectIdentity objectIdentity) {
		Assert.notNull(objectIdentity, "ObjectIdentity required");

		MutableAcl acl = getFromCache(objectIdentity);

		if (acl != null) {
			this.cache.evict(acl.getId());
			this.cache.evict(acl.getObjectIdentity());
		}
	}

	@Override
	public MutableAcl getFromCache(ObjectIdentity objectIdentity) {
		Assert.notNull(objectIdentity, "ObjectIdentity required");
		return getFromCache((Object) objectIdentity);
	}

	@Override
	public MutableAcl getFromCache(Serializable pk) {
		Assert.notNull(pk, "Primary key (identifier) required");
		return getFromCache((Object) pk);
	}

	@Override
	public void putInCache(MutableAcl acl) {
		Assert.notNull(acl, "Acl required");
		Assert.notNull(acl.getObjectIdentity(), "ObjectIdentity required");
		Assert.notNull(acl.getId(), "ID required");

		if ((acl.getParentAcl() != null) && (acl.getParentAcl() instanceof MutableAcl)) {
			putInCache((MutableAcl) acl.getParentAcl());
		}

		this.cache.put(acl.getObjectIdentity(), acl);
		this.cache.put(acl.getId(), acl);
	}

	private MutableAcl getFromCache(Object key) {
		Cache.ValueWrapper element = this.cache.get(key);

		if (element == null) {
			return null;
		}

		return initializeTransientFields((MutableAcl) element.get());
	}

	private MutableAcl initializeTransientFields(MutableAcl value) {
		if (value instanceof AclImpl) {
			FieldUtils.setProtectedFieldValue("aclAuthorizationStrategy", value, this.aclAuthorizationStrategy);
			FieldUtils.setProtectedFieldValue("permissionGrantingStrategy", value, this.permissionGrantingStrategy);
		}

		if (value.getParentAcl() != null) {
			initializeTransientFields((MutableAcl) value.getParentAcl());
		}
		return value;
	}

	@Override
	public void clearCache() {
		this.cache.clear();
	}

}
