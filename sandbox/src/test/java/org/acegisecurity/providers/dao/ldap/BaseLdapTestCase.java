package net.sf.acegisecurity.providers.dao.ldap;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.ldap.server.jndi.EnvKeys;

import junit.framework.TestCase;

/** Important note: this class merely defines certain 
 *  base properties needed by all LDAP unit tests.
 */
public class BaseLdapTestCase extends TestCase {

	protected static LdapTestHelper ldapTestHelper = new LdapTestHelper();
	
	/** Create and return a Hashtable with standard JNDI settings for our tests. */
	protected Hashtable getEnvironment() {
		Hashtable env = new Hashtable();
		env.put( Context.PROVIDER_URL, "ou=system" );
		env.put( Context.INITIAL_CONTEXT_FACTORY, "org.apache.ldap.server.jndi.ServerContextFactory" );
		env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
		env.put( Context.SECURITY_CREDENTIALS, "secret" );
		env.put( EnvKeys.WKDIR, ldapTestHelper.getTempDirectoryPath() );
		return env;
	}
	
	/** Create and return a Hashtable with standard JNDI settings for our tests. 
	 * @throws NamingException */
	protected DirContext getInitialDirContext() throws NamingException {
		 return new InitialDirContext( getEnvironment() );
	}
}
