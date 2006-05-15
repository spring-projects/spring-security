package org.acegisecurity.userdetails.ldap;

import org.acegisecurity.ldap.LdapEntryMapper;
import org.acegisecurity.GrantedAuthorityImpl;
import org.springframework.util.Assert;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsMapper implements LdapEntryMapper {
    private final Log logger = LogFactory.getLog(LdapUserDetailsMapper.class); 

    private String passwordAttributeName = "userPassword";

    private String[] roleAttributes = null;

    private String rolePrefix = "ROLE_";

    private boolean convertToUpperCase = true;

    public void setPasswordAttributeName(String passwordAttributeName) {
        this.passwordAttributeName = passwordAttributeName;
    }

    public void setRoleAttributes(String[] roleAttributes) {
        Assert.notNull(roleAttributes, "roleAttributes array cannot be null");
        this.roleAttributes = roleAttributes;
    }

    public Object mapAttributes(String dn, Attributes attributes) throws NamingException {
        LdapUserDetailsImpl.Essence essence = new LdapUserDetailsImpl.Essence();

        essence.setDn(dn);
        essence.setAttributes(attributes);

        Attribute passwordAttribute = attributes.get(passwordAttributeName);

        if(passwordAttribute != null) {
            Object retrievedPassword = passwordAttribute.get();

            if (!(retrievedPassword instanceof String)) {
                // Assume it's binary
                retrievedPassword = new String((byte[])retrievedPassword);
            }

            essence.setPassword((String)retrievedPassword);
        }

        // Map the roles

        for(int i=0; roleAttributes != null && i < roleAttributes.length; i++) {
            Attribute roleAttribute = attributes.get(roleAttributes[i]);

            NamingEnumeration attributeRoles = roleAttribute.getAll();

            while(attributeRoles.hasMore()) {
                Object role = attributeRoles.next();

                // We only handle Strings for the time being
                if(role instanceof String) {
                    if(convertToUpperCase) {
                        role = ((String)role).toUpperCase();
                    }

                    essence.addAuthority(new GrantedAuthorityImpl(rolePrefix + role));
                } else {
                    logger.warn("Non-String value found for role attribute " + roleAttribute.getID());
                }
            }
        }

        return essence.createUserDetails();
    }
}
