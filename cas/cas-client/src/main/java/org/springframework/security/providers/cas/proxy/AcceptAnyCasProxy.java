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

package org.springframework.security.providers.cas.proxy;

import org.springframework.security.providers.cas.CasProxyDecider;
import org.springframework.security.providers.cas.ProxyUntrustedException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;

import java.util.List;


/**
 * Accepts a proxied request from any other service.<P>Also accepts the request if there was no proxy (ie the user
 * directly authenticated against this service).</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AcceptAnyCasProxy implements CasProxyDecider {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(AcceptAnyCasProxy.class);

    //~ Methods ========================================================================================================

    public void confirmProxyListTrusted(List proxyList)
        throws ProxyUntrustedException {
        Assert.notNull(proxyList, "proxyList cannot be null");

        if (logger.isDebugEnabled()) {
            logger.debug("Always accepting proxy list: " + proxyList.toString());
        }
    }
}
