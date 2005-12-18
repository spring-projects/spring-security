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

package org.acegisecurity.providers.ldap.populator;

import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.providers.ldap.LdapDataAccessException;
import org.acegisecurity.providers.ldap.InitialDirContextFactory;
import org.acegisecurity.providers.ldap.LdapUtils;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.directory.DirContext;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import java.util.Set;
import java.util.HashSet;

/**
 * The default strategy for obtaining user role information from the directory.
 * <p>
 * It obtains roles by
 * <ul>
 * <li>Reading the values of the roles specified by the attribute names in the
 * <tt>userRoleAttributes</tt> </li>
 * <li>Performing a search for "groups" the user is a member of and adding
 * those to the list of roles.</li>
 * </ul>
 * </p>
 * <p>
 * If the <tt>userRolesAttributes</tt> property is set, any matching
 * attributes amongst those retrieved for the user will have their values added
 * to the list of roles.
 * If <tt>userRolesAttributes</tt> is null, no attributes will be mapped to roles.
 * </p>
 * <p>
 * A typical group search scenario would be where each group/role is specified using
 * the <tt>groupOfNames</tt> (or <tt>groupOfUniqueNames</tt>) LDAP objectClass
 * and the user's DN is listed in the <tt>member</tt> (or <tt>uniqueMember</tt>) attribute
 * to indicate that they should be assigned that role. The following LDIF sample
 * has the groups stored under the DN <tt>ou=groups,dc=acegisecurity,dc=org</tt>
 * and a group called "developers" with "ben" and "marissa" as members:
 *
 * <pre>
 * dn: ou=groups,dc=acegisecurity,dc=org
 * objectClass: top
 * objectClass: organizationalUnit
 * ou: groups
 *
 * dn: cn=developers,ou=groups,dc=acegisecurity,dc=org
 * objectClass: groupOfNames
 * objectClass: top
 * cn: developers
 * description: Acegi Security Developers
 * member: uid=ben,ou=people,dc=acegisecurity,dc=org
 * member: uid=marissa,ou=people,dc=acegisecurity,dc=org
 * ou: developer
 * </pre>
 * </p>
 * <p>
 * The group search is performed within a DN specified by the <tt>groupSearchBase</tt>
 * property, which should be relative to the root DN of its <tt>InitialDirContextFactory</tt>.
 * If the search base is null, group searching is disabled. The filter used in the search is defined by the
 * <tt>groupSearchFilter</tt> property, with the filter argument {0} being the full DN of the user. You can also specify which attribute defines the role name by
 * setting the <tt>groupRoleAttribute</tt> property (the default is "cn").
 * </p>
 * <p>
 * <pre>
 * &lt;bean id="ldapAuthoritiesPopulator" class="org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator">
 * TODO
 * &lt;/bean>
 * </pre>
 * </p>
 *
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(DefaultLdapAuthoritiesPopulator.class);

    //~ Instance fields ========================================================

    /** Attributes of the User's LDAP Object that contain role name information. */
    private String[] userRoleAttributes = null;

    private String rolePrefix = "ROLE_";

    /** The base DN from which the search for group membership should be performed */
    private String groupSearchBase = null;

    /** The pattern to be used for the user search. {0} is the user's DN */
    private String groupSearchFilter = "(member={0})";

    /** The ID of the attribute which contains the role name for a group */
    private String groupRoleAttribute = "cn";

    /** Whether group searches should be performed over the full sub-tree from the base DN */
    // private boolean searchSubtree = false;

    /** Internal variable, tied to searchSubTree property */
    private int searchScope = SearchControls.ONELEVEL_SCOPE;

    private boolean convertToUpperCase = true;

    /** An initial context factory is only required if searching for groups is required. */
    private InitialDirContextFactory initialDirContextFactory = null;

    //~ Constructors ===========================================================

    /**
     * Constructor for non-group search scenarios. Typically in this case
     * the <tt>userRoleAttributes</tt> property will be set to obtain roles directly
     * from the user's directory entry attributes.
     */
    public DefaultLdapAuthoritiesPopulator() {
    }

    /**
     * Constructor for group search scenarios. <tt>userRoleAttributes</tt> may still be
     * set as a property.
     *
     * @param initialDirContextFactory
     * @param groupSearchBase
     */
    public DefaultLdapAuthoritiesPopulator(InitialDirContextFactory initialDirContextFactory, String groupSearchBase) {
        Assert.notNull(initialDirContextFactory, "InitialDirContextFactory must not be null");
        Assert.hasLength(groupSearchBase, "The groupSearchBase (name to search under), must be specified.");
        this.initialDirContextFactory = initialDirContextFactory;
        this.groupSearchBase = groupSearchBase;
    }

    //~ Methods ================================================================

    /**
     *
     * @param username the login name passed to the authentication provider.
     * @param userDn the user's DN.
     * @param userAttributes the attributes retrieved from the user's directory entry.
     * @return the full set of roles granted to the user.
     */
    public GrantedAuthority[] getGrantedAuthorities(String username, String userDn, Attributes userAttributes) {
        logger.debug("Getting authorities for user " + userDn);

        Set roles = getRolesFromUserAttributes(userDn, userAttributes);

        Set groupRoles = getGroupMembershipRoles(userDn, userAttributes);

        if(groupRoles != null) {
            roles.addAll(groupRoles);
        }

        return (GrantedAuthority[])roles.toArray(new GrantedAuthority[roles.size()]);
    }

    protected Set getRolesFromUserAttributes(String userDn, Attributes userAttributes) {
        Set userRoles = new HashSet();

        for(int i=0; userRoleAttributes != null && i < userRoleAttributes.length; i++) {
            Attribute roleAttribute = userAttributes.get(userRoleAttributes[i]);

            addAttributeValuesToRoleSet(roleAttribute, userRoles);
        }

        return userRoles;
    }

    /**
     * Searches for groups the user is a member of.
     *
     * @param userDn the user's distinguished name.
     * @param userAttributes
     * @return the set of roles obtained from a group membership search.
     */
    protected Set getGroupMembershipRoles(String userDn, Attributes userAttributes) {
        Set userRoles = new HashSet();

        if (groupSearchBase == null) {
            return null;
        }

        if(logger.isDebugEnabled()) {
            logger.debug("Searching for roles for user '"
                    + userDn + "', with filter "+ groupSearchFilter
                    + " in search base '" + groupSearchBase + "'");
        }

        DirContext ctx = initialDirContextFactory.newInitialDirContext();
        SearchControls ctls = new SearchControls();

        ctls.setSearchScope(searchScope);
        ctls.setReturningAttributes(new String[] {groupRoleAttribute});

        try {
            NamingEnumeration groups =
                    ctx.search(groupSearchBase, groupSearchFilter, new String[]{userDn}, ctls);

            while (groups.hasMore()) {
                SearchResult result = (SearchResult) groups.next();
                Attributes attrs = result.getAttributes();

                // There should only be one role attribute.
                NamingEnumeration groupRoleAttributes = attrs.getAll();

                while(groupRoleAttributes.hasMore()) {
                    Attribute roleAttribute = (Attribute) groupRoleAttributes.next();

                    addAttributeValuesToRoleSet(roleAttribute, userRoles);
                }
            }
        } catch (NamingException e) {
            throw new LdapDataAccessException("Group search failed for user " + userDn, e);
        } finally {
            LdapUtils.closeContext(ctx);
        }

        if(logger.isDebugEnabled()) {
            logger.debug("Roles from search: " + userRoles);
        }

        return userRoles;
    }

    private void addAttributeValuesToRoleSet(Attribute roleAttribute, Set roles) {
        if(roleAttribute == null) {
            return;
        }

        try {
            NamingEnumeration attributeRoles = roleAttribute.getAll();

            while(attributeRoles.hasMore()) {
                Object role = attributeRoles.next();

                // We only handle Strings for the time being
                if(role instanceof String) {
                    if(convertToUpperCase) {
                        role = ((String)role).toUpperCase();
                    }

                    roles.add(new GrantedAuthorityImpl(rolePrefix + role));
                } else {
                    logger.warn("Non-String value found for role attribute " + roleAttribute.getID());
                }
            }
        } catch(NamingException ne) {
            throw new LdapDataAccessException("Error retrieving values for role attribute " +
                    roleAttribute.getID(), ne);
        }
    }

    protected String[] getUserRoleAttributes() {
        return userRoleAttributes;
    }

    public void setUserRoleAttributes(String[] userRoleAttributes) {
        this.userRoleAttributes = userRoleAttributes;
    }

    public void setRolePrefix(String rolePrefix) {
        Assert.notNull(rolePrefix, "rolePrefix must not be null");
        this.rolePrefix = rolePrefix;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        Assert.notNull(groupSearchFilter, "groupSearchFilter must not be null");
        this.groupSearchFilter = groupSearchFilter;
    }

    public void setGroupRoleAttribute(String groupRoleAttribute) {
        Assert.notNull(groupRoleAttribute, "groupRoleAttribute must not be null");
        this.groupRoleAttribute = groupRoleAttribute;
    }

    public void setSearchSubtree(boolean searchSubtree) {
    //    this.searchSubtree = searchSubtree;
        this.searchScope = searchSubtree ?
                SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE;
    }

    public void setConvertToUpperCase(boolean convertToUpperCase) {
        this.convertToUpperCase = convertToUpperCase;
    }
}
