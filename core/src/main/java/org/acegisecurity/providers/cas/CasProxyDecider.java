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

package org.acegisecurity.providers.cas;

import java.util.List;


/**
 * Decides whether a proxy list presented via CAS is trusted or not.
 * 
 * <P>
 * CAS 1.0 allowed services to receive a service ticket and then validate it.
 * CAS 2.0 allows services to receive a service ticket and then validate it
 * with a proxy callback URL. The callback will enable the CAS server to
 * authenticate the service. In doing so the service will receive a
 * proxy-granting ticket and a proxy-granting ticket IOU. The IOU is just an
 * internal record that a proxy-granting ticket is due to be received via the
 * callback URL.
 * </p>
 * 
 * <P>
 * With a proxy-granting ticket, a service can request the CAS server provides
 * it with a proxy ticket. A proxy ticket is just a service ticket, but the
 * CAS server internally tracks the list (chain) of services used to build the
 * proxy ticket. The proxy ticket is then presented to the target service.
 * </p>
 * 
 * <P>
 * If this application is a target service of a proxy ticket, the
 * <code>CasProxyDecider</code> resolves whether or not the proxy list is
 * trusted. Applications should only trust services they allow to impersonate
 * an end user.
 * </p>
 * 
 * <P>
 * If this application is a service that should never accept proxy-granting
 * tickets, the implementation should reject tickets that present a proxy list
 * with any members. If the list has no members, it indicates the CAS server
 * directly authenticated the user (ie there are no services which proxied the
 * user authentication).
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface CasProxyDecider {
    //~ Methods ================================================================

    /**
     * Decides whether the proxy list is trusted.
     * 
     * <P>
     * Must throw any <code>ProxyUntrustedException</code> if the proxy list is
     * untrusted.
     * </p>
     */
    public void confirmProxyListTrusted(List proxyList)
        throws ProxyUntrustedException;
}
