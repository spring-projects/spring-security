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

import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.GrantedAuthority;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;
import org.springframework.ldap.UncategorizedLdapException;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;


/**
 * The entry mapper used by the authenticators to create an ldap user object.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsMapper implements ContextMapper {
    //~ Instance fields ================================================================================================

    private final Log logger = LogFactory.getLog(LdapUserDetailsMapper.class);
    private String usernameAttributeName = "uid";
    private String passwordAttributeName = "userPassword";
    private String rolePrefix = "ROLE_";
    private String[] roleAttributes = null;
    private boolean convertToUpperCase = true;

    //~ Methods ========================================================================================================

    public Object mapFromContext(Object ctxObj) {
        Assert.isInstanceOf(DirContextAdapter.class, ctxObj, "Can only map from DirContextAdapter instances");

        DirContextAdapter ctx = (DirContextAdapter)ctxObj;
        String dn = ctx.getNameInNamespace();

        logger.debug("Mapping user details from context with DN: " + dn);

        LdapUserDetailsImpl.Essence essence = new LdapUserDetailsImpl.Essence();
        essence.setDn(dn);
        essence.setAttributes(ctx.getAttributes());

        Attribute passwordAttribute = ctx.getAttributes().get(passwordAttributeName);

        if (passwordAttribute != null) {
            essence.setPassword(mapPassword(passwordAttribute));
        }

        essence.setUsername(mapUsername(ctx));

        // Map the roles
        for (int i = 0; (roleAttributes != null) && (i < roleAttributes.length); i++) {
            String[] rolesForAttribute = ctx.getStringAttributes(roleAttributes[i]);

            if (rolesForAttribute == null) {
                logger.debug("Couldn't read role attribute '" + roleAttributes[i] + "' for user " + dn);
                continue;
            }

            for (int j = 0; j < rolesForAttribute.length; j++) {
                GrantedAuthority authority = createAuthority(rolesForAttribute[j]);

                if (authority != null) {
                    essence.addAuthority(authority);
                }
            }
        }

        return essence.createUserDetails();
        //return essence;
    }

    /**
     * Extension point to allow customized creation of the user's password from
     * the attribute stored in the directory.
     *
     * @param passwordAttribute the attribute instance containing the password
     * @return a String representation of the password.
     */
    protected String mapPassword(Attribute passwordAttribute) {
        Object retrievedPassword = null;

        try {
            retrievedPassword = passwordAttribute.get();
        } catch (NamingException e) {
            throw new UncategorizedLdapException("Failed to get password attribute", e);
        }

        if (!(retrievedPassword instanceof String)) {
            // Assume it's binary
            retrievedPassword = new String((byte[]) retrievedPassword);
        }

        return (String) retrievedPassword;

    }

    protected String mapUsername(DirContextAdapter ctx) {
        Attribute usernameAttribute = ctx.getAttributes().get(usernameAttributeName);
        String username;

        if (usernameAttribute == null) {
            throw new UncategorizedLdapException(
                    "Failed to get attribute " + usernameAttributeName + " from context");
        }

        try {
            username = (String) usernameAttribute.get();
        } catch (NamingException e) {
            throw new UncategorizedLdapException("Failed to get username from attribute " + usernameAttributeName, e);
        }

        return username;
    }

    /**
     * Creates a GrantedAuthority from a role attribute. Override to customize
     * authority object creation.
     * <p>
     * The default implementation converts string attributes to roles, making use of the <tt>rolePrefix</tt>
     * and <tt>convertToUpperCase</tt> properties. Non-String attributes are ignored.
     * </p>
     *
     * @param role the attribute returned from
     * @return the authority to be added to the list of authorities for the user, or null
     * if this attribute should be ignored.
     */
    protected GrantedAuthority createAuthority(Object role) {
        if (role instanceof String) {
            if (convertToUpperCase) {
                role = ((String) role).toUpperCase();
            }
            return new GrantedAuthorityImpl(rolePrefix + role);
        }
        return null;
    }

    /**
     * Determines whether role field values will be converted to upper case when loaded.
     * The default is true.
     *
     * @param convertToUpperCase true if the roles should be converted to upper case.
     */
    public void setConvertToUpperCase(boolean convertToUpperCase) {
        this.convertToUpperCase = convertToUpperCase;
    }

    /**
     * The name of the attribute which contains the user's password.
     * Defaults to "userPassword".
     *
     * @param passwordAttributeName the name of the attribute
     */
    public void setPasswordAttributeName(String passwordAttributeName) {
        this.passwordAttributeName = passwordAttributeName;
    }


    public void setUsernameAttributeName(String usernameAttributeName) {
        this.usernameAttributeName = usernameAttributeName;
    }

    /**
     * The names of any attributes in the user's  entry which represent application
     * roles. These will be converted to <tt>GrantedAuthority</tt>s and added to the
     * list in the returned LdapUserDetails object. The attribute values must be Strings by default.
     *
     * @param roleAttributes the names of the role attributes.
     */
    public void setRoleAttributes(String[] roleAttributes) {
        Assert.notNull(roleAttributes, "roleAttributes array cannot be null");
        this.roleAttributes = roleAttributes;
    }

    /**
     * The prefix that should be applied to the role names
     * @param rolePrefix the prefix (defaults to "ROLE_").
     */
    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }
}
