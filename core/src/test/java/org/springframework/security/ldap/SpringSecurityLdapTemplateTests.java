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

import org.springframework.ldap.UncategorizedLdapException;
import org.springframework.ldap.core.ContextExecutor;

import java.util.Set;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;


/**
 * @author Luke Taylor
 * @version $Id$
 */
public class SpringSecurityLdapTemplateTests extends AbstractLdapIntegrationTests {
    //~ Instance fields ================================================================================================

    private SpringSecurityLdapTemplate template;

    //~ Methods ========================================================================================================

    protected void onSetUp() throws Exception {
        super.onSetUp();
        template = new SpringSecurityLdapTemplate(getContextSource());
    }

    public void testCompareOfCorrectByteValueSucceeds() {
        assertTrue(template.compare("uid=bob,ou=people,dc=acegisecurity,dc=org", "userPassword", LdapUtils.getUtf8Bytes("bobspassword")));
    }

    public void testCompareOfCorrectValueSucceeds() {
        assertTrue(template.compare("uid=bob,ou=people,dc=acegisecurity,dc=org", "uid", "bob"));
    }

    public void testCompareOfWrongByteValueFails() {
        assertFalse(template.compare("uid=bob,ou=people,dc=acegisecurity,dc=org", "userPassword", LdapUtils.getUtf8Bytes("wrongvalue")));
    }

    public void testCompareOfWrongValueFails() {
        assertFalse(template.compare("uid=bob,ou=people,dc=acegisecurity,dc=org", "uid", "wrongvalue"));
    }

    public void testNameExistsForInValidNameFails() {
        assertFalse(template.nameExists("ou=doesntexist,dc=acegisecurity,dc=org"));
    }

    public void testNameExistsForValidNameSucceeds() {
        assertTrue(template.nameExists("ou=groups,dc=acegisecurity,dc=org"));
    }

    public void testNamingExceptionIsTranslatedCorrectly() {
        try {
            template.executeReadOnly(new ContextExecutor() {
                    public Object executeWithContext(DirContext dirContext) throws NamingException {
                        throw new NamingException();
                    }
                });
            fail("Expected UncategorizedLdapException on NamingException");
        } catch (UncategorizedLdapException expected) {}
    }

    public void testRoleSearchReturnsCorrectNumberOfRoles() {
        String param = "uid=ben,ou=people,dc=acegisecurity,dc=org";

        Set values = template.searchForSingleAttributeValues("ou=groups", "(member={0})", new String[] {param}, "ou");

        assertEquals("Expected 3 results from search", 3, values.size());
        assertTrue(values.contains("developer"));
        assertTrue(values.contains("manager"));
        assertTrue(values.contains("submanager"));
    }

    public void testRoleSearchForMissingAttributeFailsGracefully() {
        String param = "uid=ben,ou=people,dc=acegisecurity,dc=org";

        Set values = template.searchForSingleAttributeValues("ou=groups", "(member={0})", new String[] {param}, "mail");

        assertEquals(0, values.size());
    }
}
