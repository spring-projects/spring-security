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

package net.sf.acegisecurity.providers.cas.proxy;

import net.sf.acegisecurity.providers.cas.CasProxyDecider;
import net.sf.acegisecurity.providers.cas.ProxyUntrustedException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.util.List;


/**
 * Accepts proxied requests if the closest proxy is named in the
 * <code>validProxies</code> list.
 * 
 * <P>
 * Also accepts the request if there was no proxy (ie the user directly
 * authenticated against this service).
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class NamedCasProxyDecider implements CasProxyDecider, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(NamedCasProxyDecider.class);

    //~ Instance fields ========================================================

    private List validProxies;

    //~ Methods ================================================================

    public void setValidProxies(List validProxies) {
        this.validProxies = validProxies;
    }

    public List getValidProxies() {
        return validProxies;
    }

    public void afterPropertiesSet() throws Exception {
        if (this.validProxies == null) {
            throw new IllegalArgumentException(
                "A validProxies list must be set");
        }
    }

    public void confirmProxyListTrusted(List proxyList)
        throws ProxyUntrustedException {
        if (proxyList == null) {
            throw new IllegalArgumentException("proxyList cannot be null");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Proxy list: " + proxyList.toString());
        }

        if (proxyList.size() == 0) {
            // A Service Ticket (not a Proxy Ticket)
            return;
        }

        if (!validProxies.contains(proxyList.get(0))) {
            throw new ProxyUntrustedException("Nearest proxy '"
                + proxyList.get(0) + "' is untrusted");
        }
    }
}
