/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.ldap;

import org.springframework.security.AcegiMessageSource;
import org.springframework.security.BadCredentialsException;
import org.springframework.ldap.UncategorizedLdapException;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.directory.DirContext;

import static org.junit.Assert.*;
import org.junit.Test;

/**
 * Tests {@link org.springframework.security.ldap.DefaultInitialDirContextFactory}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultInitialDirContextFactoryTests extends AbstractLdapIntegrationTests {
    //~ Instance fields ================================================================================================

    DefaultInitialDirContextFactory idf;

    //~ Methods ========================================================================================================

    public void onSetUp() throws Exception {
        super.onSetUp();
        idf = getInitialDirContextFactory();
        idf.setMessageSource(new AcegiMessageSource());
    }

    @Test
    public void testAnonymousBindSucceeds() throws Exception {
        DirContext ctx = idf.newInitialDirContext();
        // Connection pooling should be set by default for anon users.
        // Can't rely on this property being there with embedded server
        // assertEquals("true",ctx.getEnvironment().get("com.sun.jndi.ldap.connect.pool"));
        ctx.close();
    }

    @Test
    public void testBaseDnIsParsedFromCorrectlyFromUrl() {
        idf = new DefaultInitialDirContextFactory("ldap://acegisecurity.org/dc=springframework,dc=org");
        assertEquals("dc=springframework,dc=org", idf.getRootDn());

        // Check with an empty root
        idf = new DefaultInitialDirContextFactory("ldap://acegisecurity.org/");
        assertEquals("", idf.getRootDn());

        // Empty root without trailing slash
        idf = new DefaultInitialDirContextFactory("ldap://acegisecurity.org");
        assertEquals("", idf.getRootDn());
    }

    @Test
    public void testBindAsManagerFailsIfNoPasswordSet() throws Exception {
        idf.setManagerDn("uid=bob,ou=people,dc=springframework,dc=org");

        DirContext ctx = null;

        try {
            ctx = idf.newInitialDirContext();
            fail("Binding with no manager password should fail.");

// Can't rely on this property being there with embedded server
//        assertEquals("true",ctx.getEnvironment().get("com.sun.jndi.ldap.connect.pool"));
        } catch (BadCredentialsException expected) {}

        LdapUtils.closeContext(ctx);
    }

    @Test
    public void testBindAsManagerSucceeds() throws Exception {
        idf.setManagerPassword("bobspassword");
        idf.setManagerDn("uid=bob,ou=people,dc=springframework,dc=org");

        DirContext ctx = idf.newInitialDirContext();
// Can't rely on this property being there with embedded server
//        assertEquals("true",ctx.getEnvironment().get("com.sun.jndi.ldap.connect.pool"));
        ctx.close();
    }

    @Test
    public void testConnectionAsSpecificUserSucceeds() throws Exception {
        DirContext ctx = idf.newInitialDirContext("uid=Bob,ou=people,dc=springframework,dc=org", "bobspassword");
        // We don't want pooling for specific users.
        // assertNull(ctx.getEnvironment().get("com.sun.jndi.ldap.connect.pool"));
//        com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
        ctx.close();
    }

    @Test
    public void testConnectionFailure() throws Exception {
        // Use the wrong port
        idf = new DefaultInitialDirContextFactory("ldap://localhost:60389");
        idf.setInitialContextFactory("com.sun.jndi.ldap.LdapCtxFactory");

        Hashtable env = new Hashtable();
        env.put("com.sun.jndi.ldap.connect.timeout", "200");
        idf.setExtraEnvVars(env);
        idf.setUseConnectionPool(false); // coverage purposes only

        try {
            idf.newInitialDirContext();
            fail("Connection succeeded unexpectedly");
        } catch (UncategorizedLdapException expected) {}
    }

    @Test
    public void testEnvironment() {
        idf = new DefaultInitialDirContextFactory("ldap://acegisecurity.org/");

        // check basic env
        Hashtable env = idf.getEnvironment();
        //assertEquals("com.sun.jndi.ldap.LdapCtxFactory", env.get(Context.INITIAL_CONTEXT_FACTORY));
        assertEquals("ldap://acegisecurity.org/", env.get(Context.PROVIDER_URL));
        assertEquals("simple", env.get(Context.SECURITY_AUTHENTICATION));
        assertNull(env.get(Context.SECURITY_PRINCIPAL));
        assertNull(env.get(Context.SECURITY_CREDENTIALS));

        // Ctx factory.
        idf.setInitialContextFactory("org.springframework.security.NonExistentCtxFactory");
        env = idf.getEnvironment();
        assertEquals("org.springframework.security.NonExistentCtxFactory", env.get(Context.INITIAL_CONTEXT_FACTORY));

        // Auth type
        idf.setAuthenticationType("myauthtype");
        env = idf.getEnvironment();
        assertEquals("myauthtype", env.get(Context.SECURITY_AUTHENTICATION));

        // Check extra vars
        Hashtable extraVars = new Hashtable();
        extraVars.put("extravar", "extravarvalue");
        idf.setExtraEnvVars(extraVars);
        env = idf.getEnvironment();
        assertEquals("extravarvalue", env.get("extravar"));
    }

    @Test
    public void testInvalidPasswordCausesBadCredentialsException() throws Exception {
        idf.setManagerDn("uid=bob,ou=people,dc=springframework,dc=org");
        idf.setManagerPassword("wrongpassword");

        DirContext ctx = null;

        try {
            ctx = idf.newInitialDirContext();
            fail("Binding with wrong credentials should fail.");
        } catch (BadCredentialsException expected) {}

        LdapUtils.closeContext(ctx);
    }

    @Test
    public void testMultipleProviderUrlsAreAccepted() {
        idf = new DefaultInitialDirContextFactory("ldaps://security.org/dc=springframework,dc=org "
                + "ldap://monkeymachine.co.uk/dc=springframework,dc=org");
    }

    @Test
    public void testMultipleProviderUrlsWithDifferentRootsAreRejected() {
        try {
            idf = new DefaultInitialDirContextFactory("ldap://security.org/dc=springframework,dc=org "
                    + "ldap://monkeymachine.co.uk/dc=someotherplace,dc=org");
            fail("Different root DNs should cause an exception");
        } catch (IllegalArgumentException expected) {}
    }

    @Test
    public void testSecureLdapUrlIsSupported() {
        idf = new DefaultInitialDirContextFactory("ldaps://localhost/dc=springframework,dc=org");
        assertEquals("dc=springframework,dc=org", idf.getRootDn());
    }

//    public void testNonLdapUrlIsRejected() throws Exception {
//        DefaultInitialDirContextFactory idf = new DefaultInitialDirContextFactory();
//
//        idf.setUrl("http://security.org/dc=springframework,dc=org");
//        idf.setInitialContextFactory(CoreContextFactory.class.getName());
//
//        try {
//            idf.afterPropertiesSet();
//            fail("Expected exception for non 'ldap://' URL");
//        } catch(IllegalArgumentException expected) {
//        }
//    }
    @Test
    public void testServiceLocationUrlIsSupported() {
        idf = new DefaultInitialDirContextFactory("ldap:///dc=springframework,dc=org");
        assertEquals("dc=springframework,dc=org", idf.getRootDn());
    }
}
