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
package org.acegisecurity.providers.dao.ldap.support;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.ldap.common.ldif.LdifIterator;
import org.apache.ldap.common.ldif.LdifParser;
import org.apache.ldap.common.ldif.LdifParserImpl;
import org.apache.ldap.common.message.LockableAttributesImpl;
import org.apache.ldap.common.name.LdapName;
import org.apache.ldap.server.jndi.EnvKeys;

/** 
 * Used as static field in BaseLdapTestCase;
 *  responsible for global state during JUnit tests - since 
 *  JUnit reinstantiates the test class for every method.
 *
 */
public class EmbeddedLdapServerController {
	
	private File tempDirectory;
	
	private DirContext serverContext;
	
    /**
	 * 
	 */
	public EmbeddedLdapServerController() {
        // create temporary directory for directory-server to store files in
		tempDirectory = initTempFiles();
        // start the apache directory server
		startServer();
	}
    
	/** 
     * Creates if needed a temporary directory to store the apache directory 
     * server files.  Since I can't get the class to shutdown cleanly, 
     * it also ensures a clean start by removing any files in the temp. directory.
     * 
     * @return The directory that should be used to store temporary files in.
	 */
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
    
    /** Attempts to open the file and import the contents as LDIF entries 
     *  into the test directory.
     *  
     * @param file The LDIF file to import
     * @throws IOException
     * @throws NamingException
     */
    public void importLDIF(File file) throws IOException, NamingException {
        FileInputStream fis = new FileInputStream(file);
        importLDIF(fis);
    }
    
    /** Attempts to read the provided InputStream for LDIF entries 
     *   and adds those entries to the test directory server.
     *   
     * @param in InputStream of LDIF data.
     * @throws NamingException
     * @throws IOException
     */
    public void importLDIF(InputStream in) throws NamingException, IOException {
        DirContext ctx = new InitialDirContext( getServerEnvironment() );
        try {
            LdifParser parser = new LdifParserImpl();
            LdifIterator iterator = new LdifIterator( in );
            while ( iterator.hasNext() ) {
                Attributes attributes = new LockableAttributesImpl();
                String ldif = ( String ) iterator.next();
                parser.parse( attributes, ldif );
                Name dn = new LdapName( ( String ) attributes.remove( "dn" ).get() );
                dn.remove( 0 );
                ctx.createSubcontext( dn, attributes );
            }
        } finally {
            ctx.close();
        }
    }
	
    /** starts the apache directory server. */
	protected void startServer() {
		try {
			serverContext = new InitialDirContext( getServerEnvironment() );
		} catch (NamingException nx) {
			nx.printStackTrace( System.err );
		}
	}
	
    /** stops the apache directory server, and attempts to remove 
     *  the data files that the server creates.
     */
	protected void shutdownServer() {
        // close our internal instance of the server-context
		try {
			serverContext.close();
		} catch (NamingException e) {
			e.printStackTrace( System.err );
		}
		serverContext = null;
		
        // signal the server that its time to say goodbye
		Hashtable env = getServerEnvironment();
		env.put(EnvKeys.SHUTDOWN, "true");
		try {
			new InitialDirContext( env );
		} catch (NamingException e) {
			e.printStackTrace( System.err );
		}
	}
	
    /** Utility method to remove any files in the temporary directory 
     *  that we use to store the directory server's data files.
     *  
     * @param tempDir The temporary directory.
     */
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
	
	/**
     * This isn't working, probably because I am referencing the class 
     *  as a static field, but maybe someone can figure out a way to 
     *  implement this correctly.  
     */
	public void finalize() throws Throwable {
        System.out.println("Entering LdapTestHelper.finalize()");
		shutdownServer();
		cleanupTempFiles(tempDirectory);
        tempDirectory.delete();
		super.finalize();
        System.out.println("Leaving LdapTestHelper.finalize()");
	}
	
    /**
     * @return The directory that the directory server will use to store its data files.
     */
	public File getTempDirectory() {
		return tempDirectory;
	}
	
    /**
     * @return The directory that the directory server will use to store its data files.
     */
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
	
    /** Get our reference to the server-mode context. */
	public DirContext getServerContext() {
		return serverContext;
	}

}
