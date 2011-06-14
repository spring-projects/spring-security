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

import static org.junit.Assert.*;

import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.junit.*;
import org.springframework.ldap.UncategorizedLdapException;
import org.springframework.ldap.core.ContextExecutor;
import org.springframework.security.crypto.codec.Utf8;

/**
 * @author Luke Taylor
 */
public class SpringSecurityLdapTemplateTests extends AbstractLdapIntegrationTests {
    //~ Instance fields ================================================================================================

    private SpringSecurityLdapTemplate template;

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        template = new SpringSecurityLdapTemplate(getContextSource());
    }

    @Test
    public void compareOfCorrectValueSucceeds() {
        assertTrue(template.compare("uid=bob,ou=people", "uid", "bob"));
    }

    @Test
    public void compareOfCorrectByteValueSucceeds() {
        assertTrue(template.compare("uid=bob,ou=people", "userPassword", Utf8.encode("bobspassword")));
    }

    @Test
    public void compareOfWrongByteValueFails() {
        assertFalse(template.compare("uid=bob,ou=people", "userPassword", Utf8.encode("wrongvalue")));
    }

    @Test
    public void compareOfWrongValueFails() {
        assertFalse(template.compare("uid=bob,ou=people", "uid", "wrongvalue"));
    }

//    @Test
//    public void testNameExistsForInValidNameFails() {
//        assertFalse(template.nameExists("ou=doesntexist,dc=springframework,dc=org"));
//    }
//
//    @Test
//    public void testNameExistsForValidNameSucceeds() {
//        assertTrue(template.nameExists("ou=groups,dc=springframework,dc=org"));
//    }

    @Test
    public void namingExceptionIsTranslatedCorrectly() {
        try {
            template.executeReadOnly(new ContextExecutor() {
                    public Object executeWithContext(DirContext dirContext) throws NamingException {
                        throw new NamingException();
                    }
                });
            fail("Expected UncategorizedLdapException on NamingException");
        } catch (UncategorizedLdapException expected) {}
    }

    @Test
    public void roleSearchReturnsCorrectNumberOfRoles() {
        String param = "uid=ben,ou=people,dc=springframework,dc=org";

        Set<String> values = template.searchForSingleAttributeValues("ou=groups", "(member={0})", new String[] {param}, "ou");

        assertEquals("Expected 3 results from search", 3, values.size());
        assertTrue(values.contains("developer"));
        assertTrue(values.contains("manager"));
        assertTrue(values.contains("submanager"));
    }

    @Test
    public void testRoleSearchForMissingAttributeFailsGracefully() {
        String param = "uid=ben,ou=people,dc=springframework,dc=org";

        Set<String> values = template.searchForSingleAttributeValues("ou=groups", "(member={0})", new String[] {param}, "mail");

        assertEquals(0, values.size());
    }

    @Test
    public void roleSearchWithEscapedCharacterSucceeds() throws Exception {
        String param = "cn=mouse\\, jerry,ou=people,dc=springframework,dc=org";

        Set<String> values = template.searchForSingleAttributeValues("ou=groups", "(member={0})", new String[] {param}, "cn");

        assertEquals(1, values.size());
    }

    @Test
    public void nonSpringLdapSearchCodeTestMethod() throws Exception {
        java.util.Hashtable<String, String> env = new java.util.Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:53389");
        env.put(Context.SECURITY_PRINCIPAL, "");
        env.put(Context.SECURITY_CREDENTIALS, "");

        DirContext ctx = new javax.naming.directory.InitialDirContext(env);
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningObjFlag(true);
        controls.setReturningAttributes(null);
        String param = "cn=mouse\\, jerry,ou=people,dc=springframework,dc=org";

        javax.naming.NamingEnumeration<SearchResult> results =
            ctx.search("ou=groups,dc=springframework,dc=org",
                    "(member={0})", new String[] {param},
                    controls);

        assertTrue("Expected a result", results.hasMore());
    }

    @Test
    public void searchForSingleEntryWithEscapedCharsInDnSucceeds() {
        String param = "mouse, jerry";

        template.searchForSingleEntry("ou=people", "(cn={0})", new String[] {param});
    }

}
