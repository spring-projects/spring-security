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

package org.acegisecurity.providers.cas;

import org.acegisecurity.GrantedAuthority;

import org.acegisecurity.providers.AbstractAuthenticationToken;

import org.acegisecurity.userdetails.UserDetails;

import java.io.Serializable;

import java.util.List;


/**
 * Represents a successful CAS <code>Authentication</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationToken extends AbstractAuthenticationToken implements Serializable {
    //~ Instance fields ================================================================================================

    private static final long serialVersionUID = 1L;
    private final List proxyList;
    private final Object credentials;
    private final Object principal;
    private final String proxyGrantingTicketIou;
    private final UserDetails userDetails;
    private final int keyHash;

    //~ Constructors ===================================================================================================

/**
     * Constructor.
     *
     * @param key to identify if this object made by a given {@link
     *        CasAuthenticationProvider}
     * @param principal typically the UserDetails object (cannot  be <code>null</code>)
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
    public CasAuthenticationToken(final String key, final Object principal, final Object credentials,
        final GrantedAuthority[] authorities, final UserDetails userDetails, final List proxyList,
        final String proxyGrantingTicketIou) {
        super(authorities);

        if ((key == null) || ("".equals(key)) || (principal == null) || "".equals(principal) || (credentials == null)
            || "".equals(credentials) || (authorities == null) || (userDetails == null) || (proxyList == null)
            || (proxyGrantingTicketIou == null)) {
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        }

        this.keyHash = key.hashCode();
        this.principal = principal;
        this.credentials = credentials;
        this.userDetails = userDetails;
        this.proxyList = proxyList;
        this.proxyGrantingTicketIou = proxyGrantingTicketIou;
        setAuthenticated(true);
    }

    //~ Methods ========================================================================================================

    public boolean equals(final Object obj) {
        if (!super.equals(obj)) {
            return false;
        }

        if (obj instanceof CasAuthenticationToken) {
            CasAuthenticationToken test = (CasAuthenticationToken) obj;

            // proxyGrantingTicketIou is never null due to constructor
            if (!this.getProxyGrantingTicketIou().equals(test.getProxyGrantingTicketIou())) {
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
     * @return the PGT IOU-ID or an empty <code>String</code> if no proxy callback was requested when validating the
     *         service ticket
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

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString());
        sb.append("; Credentials (Service/Proxy Ticket): ").append(this.credentials);
        sb.append("; Proxy-Granting Ticket IOU: ").append(this.proxyGrantingTicketIou);
        sb.append("; Proxy List: ").append(this.proxyList);

        return (sb.toString());
    }
}
