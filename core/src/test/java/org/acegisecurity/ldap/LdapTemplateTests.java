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

package org.acegisecurity.ldap;

import java.util.Set;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;


/**
 * 
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapTemplateTests extends AbstractLdapServerTestCase {
    //~ Instance fields ================================================================================================

    private LdapTemplate template;

    //~ Methods ========================================================================================================

    protected void onSetUp() {
        getInitialCtxFactory().setManagerDn(MANAGER_USER);
        getInitialCtxFactory().setManagerPassword(MANAGER_PASSWORD);
        template = new LdapTemplate(getInitialCtxFactory());
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
            template.execute(new LdapCallback() {
                    public Object doInDirContext(DirContext dirContext)
                        throws NamingException {
                        throw new NamingException();
                    }
                });
            fail("Expected LdapDataAccessException on NamingException");
        } catch (LdapDataAccessException expected) {}
    }

    public void testSearchForSingleAttributeValues() {
        String param = "uid=ben,ou=people,dc=acegisecurity,dc=org";

        Set values = template.searchForSingleAttributeValues("ou=groups", "(member={0})", new String[] {param}, "ou");

        assertEquals("Expected 2 results from search", 2, values.size());
        assertTrue(values.contains("developer"));
        assertTrue(values.contains("manager"));
    }
}
