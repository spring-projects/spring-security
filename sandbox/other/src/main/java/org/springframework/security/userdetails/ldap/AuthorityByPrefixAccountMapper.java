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
package org.springframework.security.userdetails.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.AuthenticationException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * Maps user (loaded from the primary user accounts repository, e.g. LDAP) to username in secondary
 * user accounts repository. Tries to find user's authority with name starting with
 * <tt>authorityPrefix</tt>.
 * 
 * 
 * @author Valery Tydykov
 * 
 */
public class AuthorityByPrefixAccountMapper implements AccountMapper, InitializingBean {
    /**
     * Logger for this class and subclasses
     */
    protected final Log logger = LogFactory.getLog(this.getClass());

    // prefix of the authority to find
    private String authorityPrefix;

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.userdetails.ldap.AccountMapper#map(org.springframework.security.userdetails.UserDetails)
     */
    public String map(UserDetails user) throws AuthenticationException {
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Mapping account=[" + user.getUsername()
                    + "]: search authorities for authority prefix=[" + this.getAuthorityPrefix()
                    + "]");
        }

        // search authorities for authority prefix
        GrantedAuthority[] authorities = user.getAuthorities();
        for (int i = 0; i < authorities.length; i++) {
            String authority = authorities[i].getAuthority();
            if (authority.startsWith(this.getAuthorityPrefix())) {
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug("Authority found=[" + authority + "]");
                }

                return authority;
            }
        }

        // not found
        // TODO message with UserDetails and authorityPrefix?
        throw new AuthorityNotFoundException(null);
    }

    /**
     * @return the authorityPrefix
     */
    public String getAuthorityPrefix() {
        return authorityPrefix;
    }

    /**
     * @param authorityPrefix the authorityPrefix to set
     */
    public void setAuthorityPrefix(String authorityPrefix) {
        Assert.hasLength(authorityPrefix, "authorityPrefix must be not empty");
        this.authorityPrefix = authorityPrefix;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(authorityPrefix, "authorityPrefix must be not empty");
    }
}
