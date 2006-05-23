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

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.Element;

import org.acegisecurity.acls.domain.AclImpl;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;

import org.springframework.util.Assert;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision$
  */
public class EhCacheBasedAclCache implements AclCache {
    //~ Instance fields ================================================================================================

    private Cache cache;

    //~ Constructors ===================================================================================================

    public EhCacheBasedAclCache(Cache cache) {
        Assert.notNull(cache, "Cache required");
        this.cache = cache;
    }

    //~ Methods ========================================================================================================

    public void evictFromCache(Long pk) {
        AclImpl acl = getFromCache(pk);

        if (acl != null) {
            cache.remove(pk);
            cache.remove(acl.getObjectIdentity());
        }
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
        if ((acl.getParentAcl() != null) && acl.getParentAcl() instanceof AclImpl) {
            putInCache((AclImpl) acl.getParentAcl());
        }

        cache.put(new Element(acl.getObjectIdentity(), acl));
        cache.put(new Element(acl.getId(), acl));
    }
}
