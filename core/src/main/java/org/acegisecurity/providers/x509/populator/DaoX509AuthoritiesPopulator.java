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

package net.sf.acegisecurity.providers.x509.populator;

import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.dao.AuthenticationDao;
import net.sf.acegisecurity.providers.x509.X509AuthoritiesPopulator;

import org.springframework.beans.factory.InitializingBean;

import java.security.cert.X509Certificate;


/**
 * Populates the X509 authorities via an {@link net.sf.acegisecurity.providers.dao.AuthenticationDao}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DaoX509AuthoritiesPopulator implements X509AuthoritiesPopulator,
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

    public UserDetails getUserDetails(X509Certificate clientCert)
        throws AuthenticationException {
        return this.authenticationDao.loadUserByUsername("marissa"/*clientCert.getSubjectDN().getName()*/);
    }

    public void afterPropertiesSet() throws Exception {
        if (this.authenticationDao == null) {
            throw new IllegalArgumentException(
                "An authenticationDao must be set");
        }
    }
}
