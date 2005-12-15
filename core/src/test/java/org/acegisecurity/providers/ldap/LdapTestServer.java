package org.acegisecurity.providers.ldap;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.apache.ldap.server.configuration.MutableServerStartupConfiguration;
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
import java.io.IOException;
import java.util.Properties;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapTestServer {

    //~ Instance fields ========================================================
    
    private DirContext serverContext;

    //~ Constructors ================================================================

    public LdapTestServer() {
        startLdapServer();
        createManagerUser();
    }

    //~ Methods ================================================================

    private void startLdapServer() {
        ApplicationContext factory = new ClassPathXmlApplicationContext( "org/acegisecurity/providers/ldap/apacheds-context.xml");
        MutableServerStartupConfiguration cfg = ( MutableServerStartupConfiguration ) factory.getBean( "configuration" );
        ClassPathResource ldifDir = new ClassPathResource("org/acegisecurity/providers/ldap/ldif");

        try {
            cfg.setLdifDirectory(ldifDir.getFile());
        } catch (IOException e) {
            System.err.println("Failed to set LDIF directory for server");
            e.printStackTrace();
        }

        Properties env = ( Properties ) factory.getBean( "environment" );

        env.setProperty( Context.PROVIDER_URL, "dc=acegisecurity,dc=org" );
        env.setProperty( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        env.putAll( cfg.toJndiEnvironment() );

        try {
            serverContext = new InitialDirContext( env );
        } catch (NamingException e) {
            System.err.println("Failed to start Apache DS");
            e.printStackTrace();
        }
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

    public DirContext getServerContext() {
        return serverContext;
    }

    public static void main(String[] args) {
        new LdapTestServer();
    }
}
