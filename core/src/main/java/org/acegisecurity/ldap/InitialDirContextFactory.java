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

package org.acegisecurity.ldap;

import org.springframework.ldap.core.ContextSource;

import javax.naming.directory.DirContext;


/**
 * Access point for obtaining LDAP contexts.
 *
 * @see org.acegisecurity.ldap.DefaultInitialDirContextFactory
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface InitialDirContextFactory extends ContextSource {
    //~ Methods ========================================================================================================

    /**
     * Returns the root DN of the contexts supplied by this factory.
     * The names for searches etc. which are performed against contexts
     * returned by this factory should be relative to the root DN.
     *
     * @return The DN of the contexts returned by this factory.
     */
    String getRootDn();

    /**
     * Provides an initial context without specific user information.
     *
     * @return An initial context for the LDAP directory
     */
    DirContext newInitialDirContext();

    /**
     * Provides an initial context by binding as a specific user.
     *
     * @param userDn the user to authenticate as when obtaining the context.
     * @param password the user's password.
     *
     * @return An initial context for the LDAP directory
     */
    DirContext newInitialDirContext(String userDn, String password);
}
