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

package net.sf.acegisecurity.providers.cas.populator;

import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.cas.CasAuthoritiesPopulator;
import net.sf.acegisecurity.providers.dao.AuthenticationDao;

import org.springframework.beans.factory.InitializingBean;


/**
 * Populates the CAS authorities via an {@link AuthenticationDao}.
 * 
 * <P>
 * The additional information (username, password, enabled status etc)  an
 * <code>AuthenticationDao</code> implementation provides about  a
 * <code>User</code> is ignored. Only the <code>GrantedAuthority</code>s are
 * relevant to this class.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoCasAuthoritiesPopulator implements CasAuthoritiesPopulator,
    InitializingBean {
    //~ Instance fields ========================================================

    private AuthenticationDao authenticationDao;

    //~ Methods ================================================================

    public void setAuthenticationDao(AuthenticationDao authenticationDao) {
        this.authenticationDao = authenticationDao;
    }

    public AuthenticationDao getAuthenticationDao() {
        return authenticationDao;
    }

    public UserDetails getUserDetails(String casUserId)
        throws AuthenticationException {
        return this.authenticationDao.loadUserByUsername(casUserId);
    }

    public void afterPropertiesSet() throws Exception {
        if (this.authenticationDao == null) {
            throw new IllegalArgumentException(
                "An authenticationDao must be set");
        }
    }
}
