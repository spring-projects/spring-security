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

import org.springframework.dao.DataAccessException;


/**
 * Used to wrap unexpected NamingExceptions while accessing the LDAP server or for other LDAP-related data problems
 * such as data we can't handle.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapDataAccessException extends DataAccessException {
    //~ Constructors ===================================================================================================

    public LdapDataAccessException(String msg) {
        super(msg);
    }

    public LdapDataAccessException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
