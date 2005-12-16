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

import org.apache.ldap.server.configuration.StartupConfiguration;
import org.apache.ldap.server.configuration.MutableDirectoryPartitionConfiguration;
import org.apache.ldap.server.configuration.MutableStartupConfiguration;
import org.apache.ldap.server.configuration.Configuration;
import org.apache.ldap.server.configuration.MutableServerStartupConfiguration;
import org.apache.ldap.server.jndi.CoreContextFactory;
import org.apache.ldap.server.jndi.ServerContextFactory;

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

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapTestServer {

    //~ Instance fields ========================================================

    private DirContext serverContext;

    private StartupConfiguration cfg;

    //~ Constructors ================================================================

    /**
     * Starts up and configures ApacheDS.
     *
     * @param embedded if false the server will listen for connections on port 10389
     *
     */
    public LdapTestServer(boolean embedded) {
        startLdapServer(embedded);
        createManagerUser();
        initTestData();
    }

    //~ Methods ================================================================


    private void startLdapServer(boolean embedded) {
        if(embedded) {
            cfg = new MutableStartupConfiguration();
        } else {
            cfg = new MutableServerStartupConfiguration();
        }

        initConfiguration();

        Properties env = new Properties();

        env.setProperty( Context.PROVIDER_URL, "dc=acegisecurity,dc=org" );
        env.setProperty( Context.INITIAL_CONTEXT_FACTORY,
                embedded ? CoreContextFactory.class.getName() : ServerContextFactory.class.getName() );
        env.putAll( cfg.toJndiEnvironment() );

        try {
            serverContext = new InitialDirContext( env );
            System.out.println("Created server context with name " + serverContext.getNameInNamespace());
        } catch (NamingException e) {
            System.err.println("Failed to start Apache DS");
            e.printStackTrace();
        }
    }


//    private void startLdapServer() {
//        ApplicationContext factory = new ClassPathXmlApplicationContext( "org/acegisecurity/providers/ldap/apacheds-context.xml");
//        MutableServerStartupConfiguration cfg = ( MutableServerStartupConfiguration ) factory.getBean( "configuration" );
//        ClassPathResource ldifDir = new ClassPathResource("org/acegisecurity/providers/ldap/ldif");
//
//        try {
//            cfg.setLdifDirectory(ldifDir.getFile());
//        } catch (IOException e) {
//            System.err.println("Failed to set LDIF directory for server");
//            e.printStackTrace();
//        }
//
//        Properties env = ( Properties ) factory.getBean( "environment" );
//
//        env.setProperty( Context.PROVIDER_URL, "dc=acegisecurity,dc=org" );
//        env.setProperty( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
//        env.putAll( cfg.toJndiEnvironment() );
//
//        try {
//            serverContext = new InitialDirContext( env );
//        } catch (NamingException e) {
//            System.err.println("Failed to start Apache DS");
//            e.printStackTrace();
//        }
//    }

    private void initTestData() {
        createOu("people");
        createOu("groups");
        createUser("bob","Bob Hamilton", "bobspassword");
        createUser("ben","Ben Alex", "{SHA}nFCebWjxfaLbHHG1Qk5UU4trbvQ=");
        String[] developers = new String[]
                {"uid=ben,ou=people,dc=acegisecurity,dc=org", "uid=bob,ou=people,dc=acegisecurity,dc=org"};
        createGroup("developers","developer",developers);
        createGroup("managers","manager",new String[] { developers[0]});
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
            System.out.println("Manager user already exists.");
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
            System.out.println(" user " + uid + " already exists.");
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
            System.out.println(" ou " + name + " already exists.");
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
            System.out.println(" group " + cn + " already exists.");
        } catch (NamingException ne) {
            System.err.println("Failed to create group.");
            ne.printStackTrace();
        }
    }

    private void initConfiguration() {
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

        if(cfg instanceof MutableServerStartupConfiguration) {
            MutableServerStartupConfiguration serverCfg = (MutableServerStartupConfiguration)cfg;
            serverCfg.setLdapPort(10389);
            serverCfg.setContextPartitionConfigurations(partitions);
        } else {
            ((MutableStartupConfiguration)cfg).setContextPartitionConfigurations(partitions);
        }
    }

    public Configuration getConfiguration() {
        return cfg;
    }

    public static void main(String[] args) {
        LdapTestServer server = new LdapTestServer(false);
    }


}
