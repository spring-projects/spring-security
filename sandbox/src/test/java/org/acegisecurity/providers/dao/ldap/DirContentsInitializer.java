package net.sf.acegisecurity.providers.dao.ldap;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

/** 
 * Since I can't get resource loading to work inside of eclipse; 
 *  for now I am writing this stuff as java. 
 *  
 * @author robert.sanders
 */
public class DirContentsInitializer {
    
    private DirContext serverContext;
    
    private DirContentsInitializer(DirContext serverContext) {
        super();
        this.serverContext = serverContext;
    }
    

    public static void initialize(DirContext serverContext) {
        DirContentsInitializer dci = new DirContentsInitializer(serverContext);
        dci.doInit();
        dci = null;
    }
    
    /** calls individual init methods. */
    private void doInit() {
        try {
            initSimpleUidUser();
            initSimpleCnUser();
        } catch (NamingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace(System.err);
        }
    }
    
    private void initSimpleUidUser() throws NamingException {
        String name = "uid=one.user,ou=users";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", name + ",ou=system");
        attrs.put("cn", "User One");
        attrs.put("sn", "One");
        attrs.put("givenName", "User");
        attrs.put("uid", "user.one");
        attrs.put("mail", "one.user@hotmail.com");
        attrs.put("userPassword", "plaintext");
        attrs.put("objectClass", "inetOrgPerson");
        attrs.put("objectClass", "top");
        
        serverContext.createSubcontext(name, attrs);
    }
    
    private void initSimpleCnUser() throws NamingException {
        String name = "cn=user.two,ou=users";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", name + ",ou=system");
        attrs.put("cn", "Two User");
        attrs.put("givenName", "Two");
        attrs.put("sn", "User");
        attrs.put("uid", "user.two");
        attrs.put("mail", "user.two@hotmail.com");
        attrs.put("userPassword", "plaintext2");
        attrs.put("objectClass", "inetOrgPerson");
        attrs.put("objectClass", "top");
        
        serverContext.createSubcontext(name, attrs);
    }
}
