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

package org.acegisecurity.providers.jaas;

import java.security.Principal;

import java.util.Set;


/**
 * The AuthorityGranter interface is used to map a given principal to role
 * names.
 * 
 * <P>
 * If a Windows NT login module were to be used from JAAS, an AuthrityGranter
 * implementation could be created to map a NT Group Principal to a ROLE_USER
 * role for instance. <br>
 * </p>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public interface AuthorityGranter {
    //~ Methods ========================================================================================================

    /**
     * The grant method is called for each principal returned from the LoginContext subject. If the
     * AuthorityGranter wishes to grant any authorities, it should return a java.util.Set containing the role names it
     * wishes to grant, such as ROLE_USER. If the AuthrityGranter does not wish to grant any authorities it should
     * return null. <br>
     * The set may contain any object as all objects in the returned set will be passed to the JaasGrantedAuthority
     * constructor using toString().
     *
     * @param principal One of the principals from the LoginContext.getSubect().getPrincipals() method.
     *
     * @return A java.util.Set of role names to grant, or null meaning no roles should be granted for the principal.
     */
    public Set grant(Principal principal);
}
