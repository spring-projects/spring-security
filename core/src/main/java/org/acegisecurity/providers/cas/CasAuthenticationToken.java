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

package net.sf.acegisecurity.providers.cas;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.AbstractAuthenticationToken;

import java.io.Serializable;

import java.util.List;


/**
 * Represents a successful CAS <code>Authentication</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationToken extends AbstractAuthenticationToken
    implements Serializable {
    //~ Instance fields ========================================================

    private List proxyList;
    private Object credentials;
    private Object principal;
    private String proxyGrantingTicketIou;
    private UserDetails userDetails;
    private GrantedAuthority[] authorities;
    private int keyHash;

    //~ Constructors ===========================================================

    /**
     * Constructor.
     *
     * @param key to identify if this object made by a given {@link
     *        CasAuthenticationProvider}
     * @param principal the username from CAS (cannot be <code>null</code>)
     * @param credentials the service/proxy ticket ID from CAS (cannot be
     *        <code>null</code>)
     * @param authorities the authorities granted to the user (from {@link
     *        CasAuthoritiesPopulator}) (cannot be <code>null</code>)
     * @param userDetails the user details (from {@link
     *        CasAuthoritiesPopulator}) (cannot be <code>null</code>)
     * @param proxyList the list of proxies from CAS (cannot be
     *        <code>null</code>)
     * @param proxyGrantingTicketIou the PGT-IOU ID from CAS (cannot be
     *        <code>null</code>, but may be an empty <code>String</code> if no
     *        PGT-IOU ID was provided)
     *
     * @throws IllegalArgumentException if a <code>null</code> was passed
     */
    public CasAuthenticationToken(String key, Object principal,
        Object credentials, GrantedAuthority[] authorities,
        UserDetails userDetails, List proxyList, String proxyGrantingTicketIou) {
        if ((key == null) || ("".equals(key)) || (principal == null)
            || "".equals(principal) || (credentials == null)
            || "".equals(credentials) || (authorities == null)
            || (userDetails == null) || (proxyList == null)
            || (proxyGrantingTicketIou == null)) {
            throw new IllegalArgumentException(
                "Cannot pass null or empty values to constructor");
        }

        for (int i = 0; i < authorities.length; i++) {
            if (authorities[i] == null) {
                throw new IllegalArgumentException("Granted authority element "
                    + i
                    + " is null - GrantedAuthority[] cannot contain any null elements");
            }
        }

        this.keyHash = key.hashCode();
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = authorities;
        this.userDetails = userDetails;
        this.proxyList = proxyList;
        this.proxyGrantingTicketIou = proxyGrantingTicketIou;
    }

    protected CasAuthenticationToken() {
        throw new IllegalArgumentException("Cannot use default constructor");
    }

    //~ Methods ================================================================

    /**
     * Ignored (always <code>true</code>).
     *
     * @param isAuthenticated ignored
     */
    public void setAuthenticated(boolean isAuthenticated) {
        // ignored
    }

    /**
     * Always returns <code>true</code>.
     *
     * @return true
     */
    public boolean isAuthenticated() {
        return true;
    }

    public GrantedAuthority[] getAuthorities() {
        return this.authorities;
    }

    public Object getCredentials() {
        return this.credentials;
    }

    public int getKeyHash() {
        return this.keyHash;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    /**
     * Obtains the proxy granting ticket IOU.
     *
     * @return the PGT IOU-ID or an empty <code>String</code> if no proxy
     *         callback was requested when validating the service ticket
     */
    public String getProxyGrantingTicketIou() {
        return proxyGrantingTicketIou;
    }

    public List getProxyList() {
        return proxyList;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }

    public boolean equals(Object obj) {
        if (!super.equals(obj)) {
            return false;
        }

        if (obj instanceof CasAuthenticationToken) {
            CasAuthenticationToken test = (CasAuthenticationToken) obj;

            // proxyGrantingTicketIou is never null due to constructor
            if (!this.getProxyGrantingTicketIou().equals(test
                    .getProxyGrantingTicketIou())) {
                return false;
            }

            // proxyList is never null due to constructor
            if (!this.getProxyList().equals(test.getProxyList())) {
                return false;
            }

            if (this.getKeyHash() != test.getKeyHash()) {
                return false;
            }

            return true;
        }

        return false;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString());
        sb.append("; Credentials (Service/Proxy Ticket): " + this.credentials);
        sb.append("; Proxy-Granting Ticket IOU: " + this.proxyGrantingTicketIou);
        sb.append("; Proxy List: " + this.proxyList.toString());

        return sb.toString();
    }
}
