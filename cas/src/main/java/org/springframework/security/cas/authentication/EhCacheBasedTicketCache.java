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

package org.springframework.security.cas.authentication;

import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Caches tickets using a Spring IoC defined
 * <a href="https://www.ehcache.org/">EHCACHE</a>.
 *
 * @author Ben Alex
 */
public class EhCacheBasedTicketCache implements StatelessTicketCache, InitializingBean {

	private static final Log logger = LogFactory.getLog(EhCacheBasedTicketCache.class);

	private Ehcache cache;

	public void afterPropertiesSet() {
		Assert.notNull(cache, "cache mandatory");
	}

	public CasAuthenticationToken getByTicketId(final String serviceTicket) {
		final Element element = cache.get(serviceTicket);

		if (logger.isDebugEnabled()) {
			logger.debug("Cache hit: " + (element != null) + "; service ticket: " + serviceTicket);
		}

		return element == null ? null : (CasAuthenticationToken) element.getValue();
	}

	public Ehcache getCache() {
		return cache;
	}

	public void putTicketInCache(final CasAuthenticationToken token) {
		final Element element = new Element(token.getCredentials().toString(), token);

		if (logger.isDebugEnabled()) {
			logger.debug("Cache put: " + element.getKey());
		}

		cache.put(element);
	}

	public void removeTicketFromCache(final CasAuthenticationToken token) {
		if (logger.isDebugEnabled()) {
			logger.debug("Cache remove: " + token.getCredentials().toString());
		}

		this.removeTicketFromCache(token.getCredentials().toString());
	}

	public void removeTicketFromCache(final String serviceTicket) {
		cache.remove(serviceTicket);
	}

	public void setCache(final Ehcache cache) {
		this.cache = cache;
	}

}
