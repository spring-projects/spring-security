/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.x509.cache;

import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.dao.UserCache;
import net.sf.acegisecurity.providers.dao.cache.EhCacheBasedUserCache;
import net.sf.acegisecurity.providers.x509.X509UserCache;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.util.Assert;

import java.security.cert.X509Certificate;


/**
 * Caches <code>User</code> objects using a Spring IoC defined <a
 * HREF="http://ehcache.sourceforge.net">EHCACHE</a>.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class EhCacheBasedX509UserCache implements X509UserCache, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(EhCacheBasedX509UserCache.class);

    //~ Instance fields ========================================================

    private Cache cache;

    //~ Methods ================================================================

    public void setCache(Cache cache) {
        this.cache = cache;
    }

    public UserDetails getUserFromCache(X509Certificate userCert) {
        Element element = null;

        try {
            element = cache.get(userCert);
        } catch (CacheException cacheException) {
            throw new DataRetrievalFailureException("Cache failure: "
                + cacheException.getMessage());
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Cache hit: " + (element != null) + "; subjectDN: "
                + userCert.getSubjectDN());
        }

        if (element == null) {
            return null;
        } else {
            return (UserDetails) element.getValue();
        }
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(cache, "cache is mandatory");
    }

    public void putUserInCache(X509Certificate userCert, UserDetails user) {
        Element element = new Element(userCert, user);

        if (logger.isDebugEnabled()) {
            logger.debug("Cache put: " + element.getKey());
        }

        cache.put(element);
    }

    public void removeUserFromCache(X509Certificate userCert) {
        if (logger.isDebugEnabled()) {
            logger.debug("Cache remove: " + userCert.getSubjectDN());
        }

        this.removeUserFromCache(userCert);
    }
}
