/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import net.sf.ehcache.CacheException;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.util.FieldUtils;
import org.springframework.util.Assert;

/**
 * Simple implementation of {@link AclCache} that delegates to EH-CACHE.
 * <p>
 * Designed to handle the transient fields in {@link AclImpl}. Note that this
 * implementation assumes all {@link AclImpl} instances share the same
 * {@link PermissionGrantingStrategy} and {@link AclAuthorizationStrategy} instances.
 *
 * @author Ben Alex
 */
public class EhCacheBasedAclCache implements AclCache {

	// ~ Instance fields
	// ================================================================================================

	private final Ehcache cache;

	private PermissionGrantingStrategy permissionGrantingStrategy;

	private AclAuthorizationStrategy aclAuthorizationStrategy;

	// ~ Constructors
	// ===================================================================================================

	public EhCacheBasedAclCache(Ehcache cache, PermissionGrantingStrategy permissionGrantingStrategy,
			AclAuthorizationStrategy aclAuthorizationStrategy) {
		Assert.notNull(cache, "Cache required");
		Assert.notNull(permissionGrantingStrategy, "PermissionGrantingStrategy required");
		Assert.notNull(aclAuthorizationStrategy, "AclAuthorizationStrategy required");
		this.cache = cache;
		this.permissionGrantingStrategy = permissionGrantingStrategy;
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
	}

	// ~ Methods
	// ========================================================================================================

	public void evictFromCache(Serializable pk) {
		Assert.notNull(pk, "Primary key (identifier) required");

		MutableAcl acl = getFromCache(pk);

		if (acl != null) {
			cache.remove(acl.getId());
			cache.remove(acl.getObjectIdentity());
		}
	}

	public void evictFromCache(ObjectIdentity objectIdentity) {
		Assert.notNull(objectIdentity, "ObjectIdentity required");

		MutableAcl acl = getFromCache(objectIdentity);

		if (acl != null) {
			cache.remove(acl.getId());
			cache.remove(acl.getObjectIdentity());
		}
	}

	public MutableAcl getFromCache(ObjectIdentity objectIdentity) {
		Assert.notNull(objectIdentity, "ObjectIdentity required");

		Element element = null;

		try {
			element = cache.get(objectIdentity);
		}
		catch (CacheException ignored) {
		}

		if (element == null) {
			return null;
		}

		return initializeTransientFields((MutableAcl) element.getValue());
	}

	public MutableAcl getFromCache(Serializable pk) {
		Assert.notNull(pk, "Primary key (identifier) required");

		Element element = null;

		try {
			element = cache.get(pk);
		}
		catch (CacheException ignored) {
		}

		if (element == null) {
			return null;
		}

		return initializeTransientFields((MutableAcl) element.getValue());
	}

	public void putInCache(MutableAcl acl) {
		Assert.notNull(acl, "Acl required");
		Assert.notNull(acl.getObjectIdentity(), "ObjectIdentity required");
		Assert.notNull(acl.getId(), "ID required");

		if (this.aclAuthorizationStrategy == null) {
			if (acl instanceof AclImpl) {
				this.aclAuthorizationStrategy = (AclAuthorizationStrategy) FieldUtils
						.getProtectedFieldValue("aclAuthorizationStrategy", acl);
				this.permissionGrantingStrategy = (PermissionGrantingStrategy) FieldUtils
						.getProtectedFieldValue("permissionGrantingStrategy", acl);
			}
		}

		if ((acl.getParentAcl() != null) && (acl.getParentAcl() instanceof MutableAcl)) {
			putInCache((MutableAcl) acl.getParentAcl());
		}

		cache.put(new Element(acl.getObjectIdentity(), acl));
		cache.put(new Element(acl.getId(), acl));
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

	public void clearCache() {
		cache.removeAll();
	}

}
