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

package net.sf.acegisecurity.providers.dao.ldap;

import junit.framework.TestCase;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;


/**
 * Important note: this class merely defines certain  base properties needed by
 * all LDAP unit tests.
 */
public class BaseLdapTestCase extends TestCase {
    //~ Static fields/initializers =============================================

    // static finalizers, they'd be nice, as LdapTestHelper 
    // never seems to get the chance to cleanup after itself
    protected static LdapTestHelper ldapTestHelper = new LdapTestHelper();

    static {
        //InputStream in = BaseLdapTestCase.class.getResourceAsStream("net/sf/acegisecurity/providers/dao/ldap/test-data.ldif");

        /* InputStream in = ldapTestHelper.getClass().getResourceAsStream("test-data.ldif");
           try {
               ldapTestHelper.importLDIF(in);
           } catch (Exception x) {
               x.printStackTrace();
               ldapTestHelper.shutdownServer();
               ldapTestHelper = null;
               throw new RuntimeException("Server initialization failed.");
           } */
        DirContentsInitializer.initialize(ldapTestHelper.getServerContext());
    }

    //~ Methods ================================================================

    protected DirContext getClientContext() throws NamingException {
        Hashtable env = new Hashtable();
        env.put(Context.PROVIDER_URL, "ldap://localhost:389/ou=system");
        env.put(Context.INITIAL_CONTEXT_FACTORY,
            "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.put(Context.SECURITY_CREDENTIALS, "secret");

        return new InitialDirContext(env);
    }

    /**
     * DOCUMENT ME!
     *
     * @return The server context for LDAP ops. used for things like
     *         addding/removing users.
     */
    protected DirContext getServerContext() {
        return ldapTestHelper.getServerContext();
    }
}
