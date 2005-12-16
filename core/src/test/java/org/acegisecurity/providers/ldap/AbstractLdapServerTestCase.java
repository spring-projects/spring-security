/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.providers.ldap;

import junit.framework.TestCase;

import java.util.Hashtable;

import org.apache.ldap.server.jndi.CoreContextFactory;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractLdapServerTestCase extends TestCase {
    protected static final String ROOT_DN = "dc=acegisecurity,dc=org";
    protected static final String MANAGER_USER = "cn=manager," + ROOT_DN;
    protected static final String MANAGER_PASSWORD = "acegisecurity";

    // External server config
//    protected static final String PROVIDER_URL = "ldap://monkeymachine:389/"+ROOT_DN;

//    // Internal server config.
//    protected static final String PROVIDER_URL = "ldap://localhost:10389/"+ROOT_DN;
    //private static final LdapTestServer SERVER = new LdapTestServer(false);

    // These values should be set for both networked configurations.
//    protected static final String CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
//    protected static final Hashtable EXTRA_ENV = new Hashtable();


    // Embedded (non-networked) server config
    private static final LdapTestServer SERVER = new LdapTestServer(true);
    protected static final String PROVIDER_URL = ROOT_DN;
    protected static final String CONTEXT_FACTORY = CoreContextFactory.class.getName();
    protected static final Hashtable EXTRA_ENV = SERVER.getConfiguration().toJndiEnvironment();

    protected AbstractLdapServerTestCase() {
    }

    protected AbstractLdapServerTestCase(String string) {
        super(string);
    }
}
