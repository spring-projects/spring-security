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

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapTemplateTests extends AbstractLdapServerTestCase {

    protected void onSetUp() {
        getInitialCtxFactory().setManagerDn(MANAGER_USER);
        getInitialCtxFactory().setManagerPassword(MANAGER_PASSWORD);
    }


    public void testCompareOfCorrectValueSucceeds() {
        LdapTemplate template = new LdapTemplate(getInitialCtxFactory());

// Doesn't work with embedded server due to bugs in apacheds
//        assertTrue(template.compare("uid=bob,ou=people", "userPassword", LdapUtils.getUtf8Bytes("bobspassword")));
    }

    public void testCompareOfWrongValueFails() {
        LdapTemplate template = new LdapTemplate(getInitialCtxFactory());

// Doesn't work with embedded server due to bugs in apacheds
//        assertFalse(template.compare("uid=bob,ou=people", "userPassword", LdapUtils.getUtf8Bytes("wrongvalue")));
    }


}
