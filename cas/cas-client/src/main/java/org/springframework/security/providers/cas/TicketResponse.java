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

package org.springframework.security.providers.cas;

import java.util.List;
import java.util.Vector;


/**
 * Represents a CAS service ticket in native CAS form.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TicketResponse {
    //~ Instance fields ================================================================================================

    private List proxyList;
    private String proxyGrantingTicketIou;
    private String user;

    //~ Constructors ===================================================================================================

/**
     * Constructor.
     *
     * <P>
     * If <code>null</code> is passed into the <code>proxyList</code> or
     * <code>proxyGrantingTicketIou</code>, suitable defaults are established.
     * However, <code>null</code> cannot be passed for the <code>user</code>
     * argument.
     * </p>
     *
     * @param user the user as indicated by CAS (cannot be <code>null</code> or
     *        an empty <code>String</code>)
     * @param proxyList as provided by CAS (may be <code>null</code>)
     * @param proxyGrantingTicketIou as provided by CAS (may be
     *        <code>null</code>)
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public TicketResponse(String user, List proxyList, String proxyGrantingTicketIou) {
        if (proxyList == null) {
            proxyList = new Vector();
        }

        if (proxyGrantingTicketIou == null) {
            proxyGrantingTicketIou = "";
        }

        if ((user == null) || "".equals(user)) {
            throw new IllegalArgumentException("Cannot pass null or empty String for User");
        }

        this.user = user;
        this.proxyList = proxyList;
        this.proxyGrantingTicketIou = proxyGrantingTicketIou;
    }

    //~ Methods ========================================================================================================

    public String getProxyGrantingTicketIou() {
        return proxyGrantingTicketIou;
    }

    public List getProxyList() {
        return proxyList;
    }

    public String getUser() {
        return user;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString());
        sb.append(": User: " + this.user);
        sb.append("; Proxy-Granting Ticket IOU: " + this.proxyGrantingTicketIou);
        sb.append("; Proxy List: " + this.proxyList.toString());

        return sb.toString();
    }
}
