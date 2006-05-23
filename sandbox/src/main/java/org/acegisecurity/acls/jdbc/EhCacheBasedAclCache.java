package org.acegisecurity.acls.jdbc;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.Element;

import org.acegisecurity.acls.domain.AclImpl;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.springframework.util.Assert;

public class EhCacheBasedAclCache implements AclCache {

	private Cache cache;
	
	public EhCacheBasedAclCache(Cache cache) {
		Assert.notNull(cache, "Cache required");
		this.cache = cache;
	}
	
	public AclImpl getFromCache(ObjectIdentity objectIdentity) {
		Element element = null;
		try {
			element = cache.get(objectIdentity);
		} catch (CacheException ignored) {}
		if (element == null) {
			return null;
		}
		return (AclImpl) element.getValue();
	}

	public AclImpl getFromCache(Long pk) {
		Element element = null;
		try {
			element = cache.get(pk);
		} catch (CacheException ignored) {}
		if (element == null) {
			return null;
		}
		return (AclImpl) element.getValue();
	}

	public void putInCache(AclImpl acl) {
		if (acl.getParentAcl() != null && acl.getParentAcl() instanceof AclImpl) {
			putInCache((AclImpl)acl.getParentAcl());
		}
		cache.put(new Element(acl.getObjectIdentity(), acl));
		cache.put(new Element(acl.getId(), acl));
	}

	public void evictFromCache(Long pk) {
		AclImpl acl = getFromCache(pk);
		if (acl != null) {
			cache.remove(pk);
			cache.remove(acl.getObjectIdentity());
		}
	}

}
