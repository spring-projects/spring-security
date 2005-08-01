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
package net.sf.acegisecurity.providers.dao.ldap;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import net.sf.acegisecurity.providers.dao.ldap.support.BaseLdapTestCase;

/** Tests to ensure the directory server we are running against is 
 *   configured as expected.
 *   
 * @author robert.sanders
 */
public class DirSetupTestCase extends BaseLdapTestCase {

    /** Simply test the connection to the test LDAP server; 
     *   if this test fails we know the server setup needs checked.
     * @throws NamingException 
     */
    public void testConnection() throws NamingException {
        Object obj = getClientContext().lookup("ou=users");
        //System.out.println( obj );
        assertNotNull( obj );
    }
    
    
    public void testSimpleUidUser() throws NamingException {
        Attributes myAttrs = getClientContext().getAttributes("uid=one.user,ou=users");
        assertEquals(8, myAttrs.size());
        assertEquals("uid=one.user,ou=users,ou=system", myAttrs.get("dn").get() );
    }
    
    public void testSimpleCnUser() throws NamingException {
        Attributes myAttrs = getClientContext().getAttributes("cn=user.two,ou=users");
        assertEquals(8, myAttrs.size());
        assertEquals("cn=user.two,ou=users,ou=system", myAttrs.get("dn").get() );
        assertEquals("Two", myAttrs.get("givenName").get() );
    }
    
    public void testOthersUsers() throws NamingException {
        Attributes myAttrs = getClientContext().getAttributes("uid=other.two,ou=others");
        assertEquals("uid=other.two,ou=others,ou=system", myAttrs.get("dn").get() );
        assertEquals("Other", myAttrs.get("givenName").get() );
    }
    
}
