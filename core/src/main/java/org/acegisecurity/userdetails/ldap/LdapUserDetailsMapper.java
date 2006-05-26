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

import org.acegisecurity.ldap.LdapEntryMapper;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;


/**
 * The entry mapper used by the authenticators to create an ldap user object.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsMapper implements LdapEntryMapper {
    //~ Instance fields ================================================================================================

    private final Log logger = LogFactory.getLog(LdapUserDetailsMapper.class);
    private String passwordAttributeName = "userPassword";
    private String rolePrefix = "ROLE_";
    private String[] roleAttributes = null;
    private boolean convertToUpperCase = true;

    //~ Methods ========================================================================================================

    public Object mapAttributes(String dn, Attributes attributes)
        throws NamingException {
        LdapUserDetailsImpl.Essence essence = new LdapUserDetailsImpl.Essence();

        essence.setDn(dn);
        essence.setAttributes(attributes);

        Attribute passwordAttribute = attributes.get(passwordAttributeName);

        if (passwordAttribute != null) {
            Object retrievedPassword = passwordAttribute.get();

            if (!(retrievedPassword instanceof String)) {
                // Assume it's binary
                retrievedPassword = new String((byte[]) retrievedPassword);
            }

            essence.setPassword((String) retrievedPassword);
        }

        // Map the roles
        for (int i = 0; (roleAttributes != null) && (i < roleAttributes.length); i++) {
            Attribute roleAttribute = attributes.get(roleAttributes[i]);

            NamingEnumeration attributeRoles = roleAttribute.getAll();

            while (attributeRoles.hasMore()) {
                Object role = attributeRoles.next();

                // We only handle Strings for the time being
                if (role instanceof String) {
                    if (convertToUpperCase) {
                        role = ((String) role).toUpperCase();
                    }

                    essence.addAuthority(new GrantedAuthorityImpl(rolePrefix + role));
                } else {
                    logger.warn("Non-String value found for role attribute " + roleAttribute.getID());
                }
            }
        }

        return essence;
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

    /**
     * The names of any attributes in the user's  entry which represent application
     * roles. These will be converted to <tt>GrantedAuthority</tt>s and added to the
     * list in the returned LdapUserDetails object.
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
