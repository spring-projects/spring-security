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

import javax.naming.directory.DirContext;


/**
 * 
DOCUMENT ME!
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class MockInitialDirContextFactory implements InitialDirContextFactory {
    //~ Instance fields ================================================================================================

    DirContext ctx;
    String baseDn;

    //~ Constructors ===================================================================================================

    public MockInitialDirContextFactory(DirContext ctx, String baseDn) {
        this.baseDn = baseDn;
        this.ctx = ctx;
    }

    //~ Methods ========================================================================================================

    public String getRootDn() {
        return baseDn;
    }

    public DirContext newInitialDirContext() {
        return ctx;
    }

    public DirContext newInitialDirContext(String username, String password) {
        return ctx;
    }
}
