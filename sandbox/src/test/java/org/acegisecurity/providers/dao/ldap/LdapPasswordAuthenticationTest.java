package net.sf.acegisecurity.providers.dao.ldap;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.GrantedAuthority;

public class LdapPasswordAuthenticationTest extends BaseLdapTestCase {
	

	/** Simply test the connection to the test LDAP server; 
	 *   if this test fails we know the server setup needs checked.
	 * @throws NamingException 
	 */
	public void testConnection() throws NamingException {
		Object obj = getClientContext().lookup("ou=users");
		//System.out.println( obj );
		assertNotNull( obj );
	}
    
    
    public void testSetupOne() throws NamingException {
        // add a simple user object so we can test it:
        
        //String name = "cn=User One,ou=users";
        String name = "uid=one.user,ou=users";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", name + ",ou=system");
        attrs.put("cn", "User One");
        attrs.put("sn", "One");
        attrs.put("givenName", "User");
        attrs.put("uid", "user.one");
        attrs.put("mail", "user.one@hotmail.com");
        attrs.put("userPassword", "plaintext");
        attrs.put("objectClass", "inetOrgPerson");
        attrs.put("objectClass", "top");
        getServerContext().createSubcontext(name, attrs);
        
        Attributes myAttrs = getClientContext().getAttributes("uid=one.user,ou=users");
        assertEquals(8, myAttrs.size());
        
        assertEquals("uid=one.user,ou=users,ou=system", myAttrs.get("dn").get() );
        //System.out.println("DN = " + myAttrs.get("dn").get() );
        /*
        NamingEnumeration names = myAttrs.getIDs();
        while (names.hasMoreElements()) {
            System.out.println("Found id: " + names.nextElement() );
        } */
    }
	
	
}
