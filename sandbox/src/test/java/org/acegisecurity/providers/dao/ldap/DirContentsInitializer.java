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
            
            initOthersGroup();
            initOthersUsers();
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
    
    private void initOthersGroup() throws NamingException {
        String otherUserOU = "ou=others";
        Attributes attrs = new BasicAttributes();
        attrs.put("dn", otherUserOU + ",ou=system");
        attrs.put("ou", "others");
        attrs.put("objectClass", "top");
        attrs.put("objectClass", "organizationalUnit");
        serverContext.createSubcontext(otherUserOU, attrs);
    }
    
    private void initOthersUsers() throws NamingException {
        String name1 = "uid=other.one,ou=others";
        Attributes attrs1 = new BasicAttributes();
        attrs1.put("dn", name1 + ",ou=system");
        attrs1.put("cn", "Other One");
        attrs1.put("givenName", "Other");
        attrs1.put("sn", "One");
        attrs1.put("uid", "other.one");
        attrs1.put("mail", "other.one@hotmail.com");
        attrs1.put("userPassword", "otherone");
        attrs1.put("objectClass", "inetOrgPerson");
        attrs1.put("objectClass", "top");
        serverContext.createSubcontext(name1, attrs1);
        
        String name2 = "uid=other.two,ou=others";
        Attributes attrs2 = new BasicAttributes();
        attrs2.put("dn", name2 + ",ou=system");
        attrs2.put("cn", "Other Two");
        attrs2.put("givenName", "Other");
        attrs2.put("sn", "Two");
        attrs2.put("uid", "other.two");
        attrs2.put("mail", "other.two@hotmail.com");
        attrs2.put("userPassword", "othertwo");
        attrs2.put("objectClass", "inetOrgPerson");
        attrs2.put("objectClass", "top");
        serverContext.createSubcontext(name2, attrs2);
    }
}
