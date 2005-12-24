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
import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.acegisecurity.providers.ldap.LdapUtils;
import org.apache.ldap.common.ldif.LdifIterator;
import org.apache.ldap.common.ldif.LdifParser;
import org.apache.ldap.common.ldif.LdifParserImpl;
import org.apache.ldap.common.message.LockableAttributesImpl;
import org.apache.ldap.common.name.LdapName;
import org.apache.ldap.server.DirectoryService;
import org.apache.ldap.server.configuration.MutableServerStartupConfiguration;
import org.apache.ldap.server.configuration.ShutdownConfiguration;
import org.apache.ldap.server.jndi.ServerContextFactory;

/**
 * Used as static field in BaseLdapTestCase;
 * responsible for global state during JUnit tests - since
 * JUnit reinstantiates the test class for every method.
 *
 * @version $Id$
 *
 */
public class EmbeddedLdapServerController {

    static final int LDAP_PORT = 10389;

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
//    public void importLDIF(File file) throws IOException, NamingException {
//        FileInputStream fis = new FileInputStream(file);
//        importLDIF(fis);
//    }

    /** Attempts to read the provided InputStream for LDIF entries
     *   and adds those entries to the test directory server.
     *
     * @param in InputStream of LDIF data.
     * @throws NamingException
     * @throws IOException
     */
    public void importLDIF(InputStream in) throws NamingException, IOException {
        LdifParser parser = new LdifParserImpl();
        LdifIterator iterator = new LdifIterator( in );

        while ( iterator.hasNext() ) {
            Attributes attributes = new LockableAttributesImpl();
            String ldif = ( String ) iterator.next();
            parser.parse( attributes, ldif );
            Name dn = new LdapName( ( String ) attributes.remove( "dn" ).get() );
            dn.remove( 0 );
            serverContext.createSubcontext( dn, attributes );
        }
    }

    /** starts the apache directory server. */
    protected void startServer() {
        System.out.println("Creating embedded LDAP server on port " + LDAP_PORT);
        MutableServerStartupConfiguration startup = new MutableServerStartupConfiguration();

        startup.setWorkingDirectory(tempDirectory);
        startup.setLdapPort(LDAP_PORT);

        Hashtable env = startup.toJndiEnvironment();
        env.putAll(getEnvironment());
        env.put(Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName());

        try {
            serverContext = new InitialDirContext( env );
        } catch (NamingException nx) {
            nx.printStackTrace();
        }
    }

    /**
     * Stops the apache directory server, and attempts to remove
     * the data files that the server creates.
     */
    protected void shutdownServer() {
        // close our internal instance of the server-context
        LdapUtils.closeContext(serverContext);
        serverContext = null;

        // signal the server that its time to say goodbye
        Hashtable env = new ShutdownConfiguration().toJndiEnvironment();
        env.putAll(getEnvironment());

        try {
            new InitialContext( env );
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Utility method to remove any files in the temporary directory
     * that we use to store the directory server's data files.
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
     * as a static field, but maybe someone can figure out a way to
     * implement this correctly.
     */
    public void finalize() throws Throwable {
        System.out.println("Entering EmbeddedLdapServerController.finalize()");
        shutdownServer();
        cleanupTempFiles(tempDirectory);
        tempDirectory.delete();
        super.finalize();
        System.out.println("Leaving EmbeddedLdapServerController.finalize()");
    }

    /**
     * @return The directory that the directory server will use to store its data files.
     */
//    public File getTempDirectory() {
//        return tempDirectory;
//    }

    /**
     * @return The directory that the directory server will use to store its data files.
     */
//    public String getTempDirectoryPath() {
//        return tempDirectory.getAbsolutePath();
//    }

    /** Create and return a Hashtable with standard JNDI settings for our tests. */
    protected Properties getEnvironment() {
        Properties env = new Properties();
        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        env.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.setProperty(Context.SECURITY_CREDENTIALS,"secret");
//        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, CoreContextFactory.class.getName());

        env.setProperty( Context.PROVIDER_URL, "ou=system" );
//		env.put( EnvKeys.WKDIR, tempDirectory.getAbsolutePath() );
        return env;
    }

    /** Get our reference to the server-mode context. */
    public DirContext getServerContext() {
        return serverContext;
    }

    public static void main(String[] args) throws IOException {
        EmbeddedLdapServerController server = new EmbeddedLdapServerController();
        System.out.println(DirectoryService.getInstance());
    }

}
