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

package org.acegisecurity.adapters;

import org.acegisecurity.GrantedAuthority;

import java.security.Principal;


/**
 * A {@link Principal} compatible  {@link org.acegisecurity.Authentication} object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PrincipalAcegiUserToken extends AbstractAdapterAuthenticationToken implements Principal {
    //~ Instance fields ================================================================================================

    private Object principal;
    private String password;
    private String username;

    //~ Constructors ===================================================================================================

    public PrincipalAcegiUserToken(String key, String username, String password, GrantedAuthority[] authorities,
        Object principal) {
        super(key, authorities);
        this.username = username;
        this.password = password;
        this.principal = principal;
    }

    //~ Methods ========================================================================================================

    public Object getCredentials() {
        return this.password;
    }

    public String getName() {
        return this.username;
    }

    public Object getPrincipal() {
        if (this.principal == null) {
            return this.username;
        }

        return this.principal;
    }
}
