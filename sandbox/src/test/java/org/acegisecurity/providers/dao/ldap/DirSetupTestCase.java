package net.sf.acegisecurity.providers.dao.ldap;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

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
    
}
