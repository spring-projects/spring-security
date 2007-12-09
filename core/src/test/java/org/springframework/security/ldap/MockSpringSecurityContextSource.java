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

import org.springframework.dao.DataAccessException;
import org.springframework.ldap.core.DistinguishedName;

import javax.naming.directory.DirContext;


/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class MockSpringSecurityContextSource implements SpringSecurityContextSource {
    //~ Instance fields ================================================================================================

    private DirContext ctx;
    private String baseDn;

    //~ Constructors ===================================================================================================

    public MockSpringSecurityContextSource() {
    }

    public MockSpringSecurityContextSource(DirContext ctx, String baseDn) {
        this.baseDn = baseDn;
        this.ctx = ctx;
    }

    //~ Methods ========================================================================================================

    public DirContext getReadOnlyContext() throws DataAccessException {
        return ctx;
    }

    public DirContext getReadWriteContext() throws DataAccessException {
        return ctx;
    }

    public DirContext getReadWriteContext(String userDn, Object credentials) {
        return ctx;
    }

    public DistinguishedName getBaseLdapPath() {
        return new DistinguishedName(baseDn);
    }

    public String getBaseLdapPathAsString() {
        return getBaseLdapPath().toString();
    }
}
