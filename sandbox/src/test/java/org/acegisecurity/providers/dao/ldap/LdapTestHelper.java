package net.sf.acegisecurity.providers.dao.ldap;

import java.io.File;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.ldap.server.jndi.EnvKeys;

/** 
 * LdapTestHelper - used as static field in BaseLdapTestCase;
 *  responsible for global state during JUnit tests - since 
 *  JUnit reinstantiates the test class for every method.
 *
 */
public class LdapTestHelper {
	
	private File tempDirectory;
	
	private DirContext serverContext;
	
    /**
	 * 
	 */
	public LdapTestHelper() {
		tempDirectory = initTempFiles();
		startServer();
	}
    
	
	protected File initTempFiles() {
		String tmpDir = System.getProperty("java.io.tmpdir");
		File dir = new File(tmpDir);
		File tmp = new File(dir, "apacheds_tmp");
		if (tmp.exists()) {
            cleanupTempFiles(tmp);
		} else {
            tmp.mkdir();
        }
        System.out.println("Directory temp files at: " + tmp.getAbsolutePath());
		return tmp;
	}
	
	protected void startServer() {
		try {
			serverContext = new InitialDirContext( getServerEnvironment() );
		} catch (NamingException nx) {
			nx.printStackTrace( System.err );
		}
	}
	
	protected void shutdownServer() {
		try {
			serverContext.close();
		} catch (NamingException e) {
			e.printStackTrace( System.err );
		}
		serverContext = null;
		
		Hashtable env = getServerEnvironment();
		env.put(EnvKeys.SHUTDOWN, "true");
		try {
			new InitialDirContext( env );
		} catch (NamingException e) {
			e.printStackTrace( System.err );
		}
	}
	
	protected void cleanupTempFiles(File tempDir) {
		if ((null != tempDir) && (tempDir.exists())) {
			File[] files = tempDir.listFiles();
			for (int i = 0; i < files.length; i++) {
				if (!files[i].delete()) {
                    System.err.println("Error: unable to cleanup Apache Directory Server file: " + files[i]);
                }
			}
		}
	}
	
	/** since file..deleteOnExit() isn't working for me, explicitly force cleanup. */
	public void finalize() throws Throwable {
        System.out.println("Entering LdapTestHelper.finalize()");
		shutdownServer();
		cleanupTempFiles(tempDirectory);
        tempDirectory.delete();
		super.finalize();
        System.out.println("Leaving LdapTestHelper.finalize()");
	}
	

	public File getTempDirectory() {
		return tempDirectory;
	}
	
	public String getTempDirectoryPath() {
		return tempDirectory.getAbsolutePath();
	}
	
	/** Create and return a Hashtable with standard JNDI settings for our tests. */
	protected Hashtable getServerEnvironment() {
		Hashtable env = new Hashtable();
		env.put( Context.PROVIDER_URL, "ou=system" );
		env.put( Context.INITIAL_CONTEXT_FACTORY, "org.apache.ldap.server.jndi.ServerContextFactory" );
		env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
		env.put( Context.SECURITY_CREDENTIALS, "secret" );
		env.put( EnvKeys.WKDIR, tempDirectory.getAbsolutePath() );
		return env;
	}
	
	public DirContext getServerContext() {
		return serverContext;
	}

}
