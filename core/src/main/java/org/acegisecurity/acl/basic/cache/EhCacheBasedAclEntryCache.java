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

package org.acegisecurity.acl.basic.cache;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.Element;

import org.acegisecurity.acl.basic.AclObjectIdentity;
import org.acegisecurity.acl.basic.BasicAclEntry;
import org.acegisecurity.acl.basic.BasicAclEntryCache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataRetrievalFailureException;

import org.springframework.util.Assert;


/**
 * Caches <code>BasicAclEntry</code>s using a Spring IoC defined <A
 * HREF="http://ehcache.sourceforge.net">EHCACHE</a>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EhCacheBasedAclEntryCache implements BasicAclEntryCache,
    InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(EhCacheBasedAclEntryCache.class);

    //~ Instance fields ========================================================

    private Cache cache;

    //~ Methods ================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(cache, "cache mandatory");
    }

    public Cache getCache() {
        return cache;
    }

    public BasicAclEntry[] getEntriesFromCache(
        AclObjectIdentity aclObjectIdentity) {
        Element element = null;

        try {
            element = cache.get(aclObjectIdentity);
        } catch (CacheException cacheException) {
            throw new DataRetrievalFailureException("Cache failure: "
                + cacheException.getMessage());
        }

        // Return null if cache element has expired or not found
        if (element == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Cache miss: " + aclObjectIdentity);
            }

            return null;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Cache hit: " + (element != null) + "; object: "
                + aclObjectIdentity);
        }

        BasicAclEntryHolder holder = (BasicAclEntryHolder) element.getValue();

        return holder.getBasicAclEntries();
    }

    public void putEntriesInCache(BasicAclEntry[] basicAclEntry) {
        BasicAclEntryHolder holder = new BasicAclEntryHolder(basicAclEntry);
        Element element = new Element(basicAclEntry[0].getAclObjectIdentity(),
                holder);

        if (logger.isDebugEnabled()) {
            logger.debug("Cache put: " + element.getKey());
        }

        cache.put(element);
    }

    public void removeEntriesFromCache(AclObjectIdentity aclObjectIdentity) {
        cache.remove(aclObjectIdentity);
    }

    public void setCache(Cache cache) {
        this.cache = cache;
    }
}
