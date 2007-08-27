/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.acegisecurity.acls.jdbc;

import net.sf.ehcache.CacheException;
import net.sf.ehcache.Element;
import net.sf.ehcache.Ehcache;

import org.acegisecurity.acls.MutableAcl;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;

import org.springframework.util.Assert;

import java.io.Serializable;


/**
 * Simple implementation of {@link AclCache} that delegates to EH-CACHE.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EhCacheBasedAclCache implements AclCache {
    //~ Instance fields ================================================================================================

    private Ehcache cache;

    //~ Constructors ===================================================================================================

    public EhCacheBasedAclCache(Ehcache cache) {
        Assert.notNull(cache, "Cache required");
        this.cache = cache;
    }

    //~ Methods ========================================================================================================

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
        } catch (CacheException ignored) {}

        if (element == null) {
            return null;
        }

        return (MutableAcl) element.getValue();
    }

    public MutableAcl getFromCache(Serializable pk) {
        Assert.notNull(pk, "Primary key (identifier) required");

        Element element = null;

        try {
            element = cache.get(pk);
        } catch (CacheException ignored) {}

        if (element == null) {
            return null;
        }

        return (MutableAcl) element.getValue();
    }

    public void putInCache(MutableAcl acl) {
        Assert.notNull(acl, "Acl required");
        Assert.notNull(acl.getObjectIdentity(), "ObjectIdentity required");
        Assert.notNull(acl.getId(), "ID required");

        if ((acl.getParentAcl() != null) && (acl.getParentAcl() instanceof MutableAcl)) {
            putInCache((MutableAcl) acl.getParentAcl());
        }

        cache.put(new Element(acl.getObjectIdentity(), acl));
        cache.put(new Element(acl.getId(), acl));
    }
}
