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

import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.GrantedAuthority;


/**
 * Populates the <code>GrantedAuthority[]</code> objects for a CAS
 * authenticated user.
 * 
 * <P>
 * CAS does not provide the authorities (roles) granted to a user. It merely
 * authenticates their identity. As the Acegi Security System for Spring needs
 * to know the authorities granted to a user in order to construct a valid
 * <code>Authentication</code> object, implementations of this interface will
 * provide this information.
 * </p>
 * 
 * <P>
 * Implementations should not perform any caching. They will only be called
 * when a refresh is required.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface CasAuthoritiesPopulator {
    //~ Methods ================================================================

    /**
     * Obtains the granted authorities for the specified user.
     * 
     * <P>
     * May throw any <code>AuthenticationException</code> or return
     * <code>null</code> if the authorities are unavailable.
     * </p>
     *
     * @param casUserId as obtained from the CAS validation service
     *
     * @return the granted authorities for the indicated user
     */
    public GrantedAuthority[] getAuthorities(String casUserId)
        throws AuthenticationException;
}
