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

package org.acegisecurity.providers.cas.proxy;

import org.acegisecurity.providers.cas.CasProxyDecider;
import org.acegisecurity.providers.cas.ProxyUntrustedException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import java.util.List;


/**
 * Accepts no proxied requests.
 * 
 * <P>
 * This class should be used if only service tickets wish to be accepted (ie no
 * proxy tickets at all).
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RejectProxyTickets implements CasProxyDecider {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(RejectProxyTickets.class);

    //~ Methods ================================================================

    public void confirmProxyListTrusted(List proxyList)
        throws ProxyUntrustedException {
        Assert.notNull(proxyList, "proxyList cannot be null");

        if (proxyList.size() == 0) {
            // A Service Ticket (not a Proxy Ticket)
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Proxies are unacceptable; proxy list provided: "
                    + proxyList.toString());
        }

        throw new ProxyUntrustedException("Proxy tickets are rejected");
    }
}
