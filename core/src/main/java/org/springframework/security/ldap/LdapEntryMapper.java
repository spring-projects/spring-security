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

package org.springframework.security.ldap;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;


/**
 * A mapper for use with {@link SpringSecurityLdapTemplate}. Creates a customized object from
 * a set of attributes retrieved from a directory entry.
 *
 * @author Luke Taylor
 * @deprecated in favour of Spring LDAP ContextMapper
 * @version $Id$
 */
public interface LdapEntryMapper {
    //~ Methods ========================================================================================================

    Object mapAttributes(String dn, Attributes attributes)
        throws NamingException;
}
