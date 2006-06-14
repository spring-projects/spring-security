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

package org.acegisecurity.userdetails.ldap;

import junit.framework.TestCase;

import javax.naming.directory.BasicAttributes;
import javax.naming.directory.BasicAttribute;

/**
 * Tests {@link LdapUserDetailsMapper}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsMapperTests extends TestCase {


    public void testMultipleRoleAttributeValuesAreMappedToAuthorities() throws Exception {
        LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();
        mapper.setConvertToUpperCase(false);
        mapper.setRolePrefix("");

        mapper.setRoleAttributes(new String[] {"userRole"});

        BasicAttributes attrs = new BasicAttributes();
        BasicAttribute roleAttribute = new BasicAttribute("userRole");
        roleAttribute.add("X");
        roleAttribute.add("Y");
        roleAttribute.add("Z");
        attrs.put(roleAttribute);

        LdapUserDetailsImpl.Essence user = (LdapUserDetailsImpl.Essence) mapper.mapAttributes("cn=someName", attrs);

        assertEquals(3, user.getGrantedAuthorities().length);
    }

    /**
     * SEC-303. Non-retrieved role attribute causes NullPointerException
     */
    public void testNonRetrievedRoleAttributeIsIgnored() throws Exception {
        LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();

        mapper.setRoleAttributes(new String[] {"userRole", "nonRetrievedAttribute"});

        BasicAttributes attrs = new BasicAttributes();
        attrs.put(new BasicAttribute("userRole", "x"));

        LdapUserDetailsImpl.Essence user = (LdapUserDetailsImpl.Essence) mapper.mapAttributes("cn=someName", attrs);

        assertEquals(1, user.getGrantedAuthorities().length);
        assertEquals("ROLE_X", user.getGrantedAuthorities()[0].getAuthority());
    }
}
