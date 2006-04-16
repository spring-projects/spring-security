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

package org.acegisecurity.ldap;

import org.apache.ldap.server.configuration.MutableDirectoryPartitionConfiguration;
import org.apache.ldap.server.configuration.MutableStartupConfiguration;
import org.apache.ldap.server.configuration.Configuration;
import org.apache.ldap.server.jndi.CoreContextFactory;
import org.acegisecurity.ldap.LdapUtils;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.NameAlreadyBoundException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import java.util.Properties;
import java.util.Set;
import java.util.HashSet;
import java.io.File;

/**
 * An embedded LDAP test server, complete with test data for running the
 * unit tests against.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapTestServer {

    //~ Instance fields ========================================================

    private DirContext serverContext;

    private MutableStartupConfiguration cfg;

    // Move the working dir to the temp directory
    private File workingDir = new File( System.getProperty("java.io.tmpdir")
            + File.separator + "apacheds-work" );


    //~ Constructors ================================================================

    /**
     * Starts up and configures ApacheDS.
     */
    public LdapTestServer() {
        startLdapServer();
        createManagerUser();
        initTestData();
    }

    //~ Methods ================================================================

    private void startLdapServer() {

        cfg = new MutableStartupConfiguration();
        ((MutableStartupConfiguration)cfg).setWorkingDirectory(workingDir);

        System.out.println("Working directory is " + workingDir.getAbsolutePath());

        initConfiguration();

        Properties env = new Properties();

        env.setProperty( Context.PROVIDER_URL, "dc=acegisecurity,dc=org" );
        env.setProperty( Context.INITIAL_CONTEXT_FACTORY, CoreContextFactory.class.getName());
        env.putAll( cfg.toJndiEnvironment() );

        try {
            serverContext = new InitialDirContext( env );
        } catch (NamingException e) {
            System.err.println("Failed to start Apache DS");
            e.printStackTrace();
        }
    }

    private void initTestData() {
        createOu("people");
        createOu("groups");
        createUser("bob","Bob Hamilton", "bobspassword");
        createUser("ben","Ben Alex", "{SHA}nFCebWjxfaLbHHG1Qk5UU4trbvQ=");
        String[] developers = new String[]
                {"uid=ben,ou=people,dc=acegisecurity,dc=org", "uid=bob,ou=people,dc=acegisecurity,dc=org"};
        createGroup("developers","developer",developers);
        createGroup("managers","manager", new String[] { developers[0]});
    }

    private void createManagerUser() {
        Attributes user = new BasicAttributes( "cn", "manager" , true );
        user.put( "userPassword", "acegisecurity" );
        Attribute objectClass = new BasicAttribute("objectClass");
        user.put( objectClass );
        objectClass.add( "top" );
        objectClass.add( "person" );
        objectClass.add( "organizationalPerson" );
        objectClass.add( "inetOrgPerson" );
        user.put( "sn", "Manager" );
        user.put( "cn", "manager" );
        try {
            serverContext.createSubcontext("cn=manager", user );
        } catch(NameAlreadyBoundException ignore) {
 //           System.out.println("Manager user already exists.");
        } catch (NamingException ne) {
            System.err.println("Failed to create manager user.");
            ne.printStackTrace();
        }
    }

    public void createUser( String uid, String cn, String password ) {
        Attributes user = new BasicAttributes("uid", uid);
        user.put( "cn", cn);
        user.put( "userPassword", LdapUtils.getUtf8Bytes(password) );
        Attribute objectClass = new BasicAttribute( "objectClass" );
        user.put( objectClass );
        objectClass.add( "top" );
        objectClass.add( "person" );
        objectClass.add( "organizationalPerson" );
        objectClass.add( "inetOrgPerson" );
        user.put( "sn", uid );

        try {
            serverContext.createSubcontext( "uid="+uid+",ou=people", user );
        } catch(NameAlreadyBoundException ignore) {
//            System.out.println(" user " + uid + " already exists.");
        } catch (NamingException ne) {
            System.err.println("Failed to create  user.");
            ne.printStackTrace();
        }
    }

    public void createOu(String name) {
        Attributes ou = new BasicAttributes( "ou", name );
        Attribute objectClass = new BasicAttribute( "objectClass" );
        objectClass.add("top");
        objectClass.add("organizationalUnit");
        ou.put(objectClass);

        try {
            serverContext.createSubcontext( "ou="+name, ou);
        } catch(NameAlreadyBoundException ignore) {
 //           System.out.println(" ou " + name + " already exists.");
        } catch (NamingException ne) {
            System.err.println("Failed to create ou.");
            ne.printStackTrace();
        }

    }

    public void createGroup( String cn, String ou, String[] memberDns ) {
        Attributes group = new BasicAttributes("cn", cn);
        Attribute members = new BasicAttribute("member");
        Attribute orgUnit = new BasicAttribute("ou", ou);

        for(int i=0; i < memberDns.length; i++) {
            members.add(memberDns[i]);
        }

        Attribute objectClass = new BasicAttribute( "objectClass" );
        objectClass.add( "top" );
        objectClass.add( "groupOfNames" );

        group.put(objectClass);
        group.put(members);
        group.put(orgUnit);

        try {
            serverContext.createSubcontext( "cn="+cn+",ou=groups", group );
        } catch(NameAlreadyBoundException ignore) {
//            System.out.println(" group " + cn + " already exists.");
        } catch (NamingException ne) {
            System.err.println("Failed to create group.");
            ne.printStackTrace();
        }
    }

    private void initConfiguration() {

        // Create the partition for the acegi tests
        MutableDirectoryPartitionConfiguration acegiDit = new MutableDirectoryPartitionConfiguration();
        acegiDit.setName("acegisecurity");
        acegiDit.setSuffix("dc=acegisecurity,dc=org");
        BasicAttributes attributes = new BasicAttributes();
        BasicAttribute objectClass = new BasicAttribute("objectClass");
        objectClass.add("top");
        objectClass.add("domain");
        objectClass.add("extensibleObject");
        attributes.put(objectClass);
        acegiDit.setContextEntry(attributes);

        Set indexedAttrs = new HashSet();
        indexedAttrs.add("objectClass");
        indexedAttrs.add("uid");
        indexedAttrs.add("cn");
        indexedAttrs.add("ou");
        indexedAttrs.add("member");

        acegiDit.setIndexedAttributes(indexedAttrs);

        Set partitions = new HashSet();
        partitions.add(acegiDit);

        cfg.setContextPartitionConfigurations(partitions);
    }

    public Configuration getConfiguration() {
        return cfg;
    }

    public static void main(String[] args) {
        LdapTestServer server = new LdapTestServer();
    }

}
