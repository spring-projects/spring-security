package net.sf.acegisecurity.providers.dao.ldap;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import junit.framework.TestCase;

/** Important note: this class merely defines certain 
 *  base properties needed by all LDAP unit tests.
 */
public class BaseLdapTestCase extends TestCase {

    // static finalizers, they'd be nice, as LdapTestHelper 
    // never seems to get the chance to cleanup after itself
	protected static LdapTestHelper ldapTestHelper = new LdapTestHelper();
	
	protected DirContext ctx;
	
	protected void setUp() throws NamingException {
		ctx = getClientContext();
	}
	
	protected void tearDown() throws NamingException {
		ctx.close();
		ctx = null;
	}
	
	
	protected DirContext getClientContext() throws NamingException {
		Hashtable env = new Hashtable();
		env.put( Context.PROVIDER_URL, "ldap://localhost:389/ou=system" );
		env.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory" );
		//env.put( Context.SECURITY_PRINCIPAL, "uid=admin" );
		//env.put( Context.SECURITY_CREDENTIALS, "secret" );
		return new InitialDirContext( env );
	}
	
	/** @return The server context for LDAP ops. used for things like addding/removing users. */
	protected DirContext getServerContext() {
		return ldapTestHelper.getServerContext();
	}
	
}
