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

package net.sf.acegisecurity.providers.cas.cache;

import net.sf.acegisecurity.providers.cas.CasAuthenticationToken;
import net.sf.acegisecurity.providers.cas.StatelessTicketCache;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataRetrievalFailureException;


/**
 * Caches tickets using  <A HREF="http://ehcache.sourceforge.net">EHCACHE</a>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EhCacheBasedTicketCache implements StatelessTicketCache,
    InitializingBean {
    //~ Instance fields ========================================================

    private Cache cache;
    private CacheManager manager;
    private int minutesToIdle = 20;

    //~ Methods ================================================================

    public CasAuthenticationToken getByTicketId(String serviceTicket) {
        Element element = null;

        try {
            element = cache.get(serviceTicket);
        } catch (CacheException cacheException) {
            throw new DataRetrievalFailureException("Cache failure: "
                + cacheException.getMessage());
        }

        if (element == null) {
            System.out.println("not found");

            return null;
        } else {
            System.out.println("found");

            return (CasAuthenticationToken) element.getValue();
        }
    }

    public void setMinutesToIdle(int minutesToIdle) {
        this.minutesToIdle = minutesToIdle;
    }

    /**
     * Specifies how many minutes an entry will remain in the cache from  when
     * it was last accessed. This is effectively the session duration.
     * 
     * <P>
     * Defaults to 20 minutes.
     * </p>
     *
     * @return Returns the minutes an element remains in the cache
     */
    public int getMinutesToIdle() {
        return minutesToIdle;
    }

    public void afterPropertiesSet() throws Exception {
        manager = CacheManager.create();

        // Cache name, max memory, overflowToDisk, eternal, timeToLive, timeToIdle
        cache = new Cache("ehCacheBasedTicketCache", Integer.MAX_VALUE, false,
                false, minutesToIdle * 60, minutesToIdle * 60);
        manager.addCache(cache);
    }

    public void putTicketInCache(CasAuthenticationToken token) {
        Element element = new Element(token.getCredentials().toString(), token);
        System.out.println("Adding " + element.getKey());
        cache.put(element);
    }

    public void removeTicketFromCache(CasAuthenticationToken token) {
        this.removeTicketFromCache(token.getCredentials().toString());
    }

    public void removeTicketFromCache(String serviceTicket) {
        cache.remove(serviceTicket);
    }
}
