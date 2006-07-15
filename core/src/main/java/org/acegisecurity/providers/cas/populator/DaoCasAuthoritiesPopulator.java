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

package org.acegisecurity.providers.cas.populator;

import org.acegisecurity.AuthenticationException;

import org.acegisecurity.providers.cas.CasAuthoritiesPopulator;

import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;


/**
 * Populates the CAS authorities via an {@link UserDetailsService}.<P>The additional information (username,
 * password, enabled status etc)  an <code>AuthenticationDao</code> implementation provides about  a <code>User</code>
 * is ignored. Only the <code>GrantedAuthority</code>s are relevant to this class.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoCasAuthoritiesPopulator implements CasAuthoritiesPopulator, InitializingBean {
    //~ Instance fields ================================================================================================

    private UserDetailsService userDetailsService;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService, "An authenticationDao must be set");
    }

    public UserDetails getUserDetails(String casUserId)
        throws AuthenticationException {
        return this.userDetailsService.loadUserByUsername(casUserId);
    }

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
