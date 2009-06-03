package org.springframework.security.ldap;

import static org.junit.Assert.assertNull;

import javax.naming.directory.DirContext;

import org.junit.Test;
import org.springframework.security.BadCredentialsException;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultSpringSecurityContextSourceTests extends AbstractLdapIntegrationTests {

    @Test
    public void instantiationSucceeds() {
        new DefaultSpringSecurityContextSource("ldap://blah:789/dc=springframework,dc=org");
    }

    @Test
    public void supportsSpacesInUrl() {
        new DefaultSpringSecurityContextSource("ldap://myhost:10389/dc=spring%20framework,dc=org");
    }

    @Test
    public void poolingIsntUsedForSingleUser() throws Exception {
        DirContext ctx = getContextSource().getReadWriteContext("uid=Bob,ou=people,dc=springframework,dc=org", "bobspassword");
        //com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
        assertNull(ctx.getEnvironment().get("com.sun.jndi.ldap.connect.pool"));
        ctx.close();
    }

    @Test(expected=BadCredentialsException.class)
    public void poolingIsntUsedForSingleUser2() throws Exception {
        DirContext ctx = getContextSource().getReadWriteContext("uid=Bob,ou=people,dc=springframework,dc=org", "bobspassword");
        com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
        ctx.close();
        com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
        // Now get it gain, with wrong password
        ctx = getContextSource().getReadWriteContext("uid=Bob,ou=people,dc=springframework,dc=org", "wrongpassword");
        com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
    }


}
