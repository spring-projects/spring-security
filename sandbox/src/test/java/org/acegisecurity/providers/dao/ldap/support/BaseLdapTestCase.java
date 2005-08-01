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

package net.sf.acegisecurity.providers.dao.ldap.support;

import junit.framework.TestCase;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;



/**
 * This class defines certain base properties needed by
 * all LDAP unit tests.  It also uses the EmbeddedLdapServerController to 
 * bootstrap an 'embedded' instance of the Apache Directory Server to 
 * run the Unit tests against.
 */
public class BaseLdapTestCase extends TestCase {
    //~ Static fields/initializers =============================================

    // static finalizers, they'd be nice, as the EmbeddedLdapServerController 
    // never seems to get the chance to cleanup after itself
	// Maybe JUnit4 will include such a thing.
    protected static EmbeddedLdapServerController embeddedLdapServerController = new EmbeddedLdapServerController();

    static {
    	try {
			LdapDirInitializer.intializeDir( embeddedLdapServerController.getServerContext() );
		} catch (NamingException e) {
			System.out.println("Error: unable to initialize LDAP Server for Unit tests.");
			System.out.println("    Unable to continue testing LDAP Authentication Dao without LDAP Server.");
			e.printStackTrace();
		}
    }

    /** Returns a 'client' connection to the embedded LDAP Server, using 
     *  JNDI to connect.
     */
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
     * This is a LDAP DirContext which connects directly to the 
     * embedded Apache Directory Server against which the Unit tests 
     * are run, as such the normal Unit tests should never need to 
     * reference it (with the possible exception of comparing return values 
     * between the Server Context and the Client Context).
     * 
     * @see net.sf.acegisecurity.providers.dao.ldap.support.EmbeddedLdapServerController
     * @see net.sf.acegisecurity.providers.dao.ldap.support.LdapDirInitializer
     *
     * @return The server context for LDAP operations; used for things like
     *         addding/removing users to to test against.
     */
    protected DirContext getServerContext() {
        return embeddedLdapServerController.getServerContext();
    }
    
}
