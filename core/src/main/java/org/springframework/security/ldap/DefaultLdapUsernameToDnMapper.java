package org.springframework.security.ldap;

import org.springframework.ldap.core.DistinguishedName;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLdapUsernameToDnMapper implements LdapUsernameToDnMapper {
    private String userDnBase;
    private String usernameAttribute;

   /**
    * This implementation appends a name component to the <tt>userDnBase</tt> context using the
    * <tt>usernameAttributeName</tt> property. So if the <tt>uid</tt> attribute is used to store the username, and the
    * base DN is <tt>cn=users</tt> and we are creating a new user called "sam", then the DN will be
    * <tt>uid=sam,cn=users</tt>.
    *
    * @param userDnBase the base name of the DN
    * @param usernameAttribute the attribute to append for the username component.
    */
    public DefaultLdapUsernameToDnMapper(String userDnBase, String usernameAttribute) {
        this.userDnBase = userDnBase;
        this.usernameAttribute = usernameAttribute;
    }

    public DistinguishedName buildDn(String username) {
        DistinguishedName dn = new DistinguishedName(userDnBase);

        dn.add(usernameAttribute, username);

        return dn;
    }
}
