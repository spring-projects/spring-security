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

package org.acegisecurity.providers.ldap.populator;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapTemplate;

import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;

import org.acegisecurity.userdetails.ldap.LdapUserDetails;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;


/**
 * The default strategy for obtaining user role information from the directory.
 * <p/>
 * <p>It obtains roles by performing a search for "groups" the user is a member of.</p>
 * <p/>
 * <p/>
 * A typical group search scenario would be where each group/role is specified using the <tt>groupOfNames</tt>
 * (or <tt>groupOfUniqueNames</tt>) LDAP objectClass and the user's DN is listed in the <tt>member</tt> (or
 * <tt>uniqueMember</tt>) attribute to indicate that they should be assigned that role. The following LDIF sample has
 * the groups stored under the DN <tt>ou=groups,dc=acegisecurity,dc=org</tt> and a group called "developers" with
 * "ben" and "marissa" as members:
 * <pre>
 * dn: ou=groups,dc=acegisecurity,dc=orgobjectClass: top
 * objectClass: organizationalUnitou: groupsdn: cn=developers,ou=groups,dc=acegisecurity,dc=org
 * objectClass: groupOfNamesobjectClass: topcn: developersdescription: Acegi Security Developers
 * member: uid=ben,ou=people,dc=acegisecurity,dc=orgmember: uid=marissa,ou=people,dc=acegisecurity,dc=orgou: developer
 * </pre>
 * </p>
 * <p/>
 * The group search is performed within a DN specified by the <tt>groupSearchBase</tt> property, which should
 * be relative to the root DN of its <tt>InitialDirContextFactory</tt>. If the search base is null, group searching is
 * disabled. The filter used in the search is defined by the <tt>groupSearchFilter</tt> property, with the filter
 * argument {0} being the full DN of the user. You can also optionally use the parameter {1}, which will be substituted
 * with the username. You can also specify which attribute defines the role name by setting
 * the <tt>groupRoleAttribute</tt> property (the default is "cn").</p>
 * <p/>
 * <p>The configuration below shows how the group search might be performed with the above schema.
 * <pre>
 * &lt;bean id="ldapAuthoritiesPopulator"
 *         class="org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator">
 *   &lt;constructor-arg>&lt;ref local="initialDirContextFactory"/>&lt;/constructor-arg>
 *   &lt;constructor-arg>&lt;value>ou=groups&lt;/value>&lt;/constructor-arg>
 *   &lt;property name="groupRoleAttribute">&lt;value>ou&lt;/value>&lt;/property>
 * &lt;!-- the following properties are shown with their default values -->
 *   &lt;property name="searchSubTree">&lt;value>false&lt;/value>&lt;/property>
 *   &lt;property name="rolePrefix">&lt;value>ROLE_&lt;/value>&lt;/property>
 *   &lt;property name="convertToUpperCase">&lt;value>true&lt;/value>&lt;/property>
 * &lt;/bean>
 * </pre>
 * A search for roles for user "uid=ben,ou=people,dc=acegisecurity,dc=org" would return the single granted authority
 * "ROLE_DEVELOPER".
 * </p>
 * <p/>
 * The single-level search is performed by default. Setting the <tt>searchSubTree</tt> property to true will enable
 * a search of the entire subtree under <tt>groupSearchBase</tt>.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(DefaultLdapAuthoritiesPopulator.class);

    //~ Instance fields ================================================================================================

    /**
     * A default role which will be assigned to all authenticated users if set
     */
    private GrantedAuthority defaultRole = null;

    /**
     * An initial context factory is only required if searching for groups is required.
     */
    private InitialDirContextFactory initialDirContextFactory = null;
    private LdapTemplate ldapTemplate;

    /**
     * Controls used to determine whether group searches should be performed over the full sub-tree from the
     * base DN. Modified by searchSubTree property
     */
    private SearchControls searchControls = new SearchControls();

    /**
     * The ID of the attribute which contains the role name for a group
     */
    private String groupRoleAttribute = "cn";

    /**
     * The base DN from which the search for group membership should be performed
     */
    private String groupSearchBase = null;

    /**
     * The pattern to be used for the user search. {0} is the user's DN
     */
    private String groupSearchFilter = "(member={0})";

    /**
     * Attributes of the User's LDAP Object that contain role name information.
     */

//    private String[] userRoleAttributes = null;
    private String rolePrefix = "ROLE_";
    private boolean convertToUpperCase = true;

    //~ Constructors ===================================================================================================

    /**
     * Constructor for group search scenarios. <tt>userRoleAttributes</tt> may still be
     * set as a property.
     *
     * @param initialDirContextFactory supplies the contexts used to search for user roles.
     * @param groupSearchBase          if this is an empty string the search will be performed from the root DN of the
     *                                 context factory.
     */
    public DefaultLdapAuthoritiesPopulator(InitialDirContextFactory initialDirContextFactory, String groupSearchBase) {
        this.setInitialDirContextFactory(initialDirContextFactory);
        this.setGroupSearchBase(groupSearchBase);
    }

    //~ Methods ========================================================================================================

    /**
     * This method should be overridden if required to obtain any additional
     * roles for the given user (on top of those obtained from the standard
     * search implemented by this class).
     *
     * @param ldapUser the user who's roles are required
     * @return the extra roles which will be merged with those returned by the group search
     */

    protected Set getAdditionalRoles(LdapUserDetails ldapUser) {
        return null;
    }

    /**
     * Obtains the authorities for the user who's directory entry is represented by
     * the supplied LdapUserDetails object.
     *
     * @param userDetails the user who's authorities are required
     * @return the set of roles granted to the user.
     */
    public final GrantedAuthority[] getGrantedAuthorities(LdapUserDetails userDetails) {
        String userDn = userDetails.getDn();

        if (logger.isDebugEnabled()) {
            logger.debug("Getting authorities for user " + userDn);
        }

        Set roles = getGroupMembershipRoles(userDn, userDetails.getUsername());

        // Temporary use of deprecated method
        Set oldGroupRoles = getGroupMembershipRoles(userDn, userDetails.getAttributes());

        if (oldGroupRoles != null) {
            roles.addAll(oldGroupRoles);
        }

        Set extraRoles = getAdditionalRoles(userDetails);

        if (extraRoles != null) {
            roles.addAll(extraRoles);
        }

        if (defaultRole != null) {
            roles.add(defaultRole);
        }

        return (GrantedAuthority[]) roles.toArray(new GrantedAuthority[roles.size()]);
    }

//    protected Set getRolesFromUserAttributes(String userDn, Attributes userAttributes) {
//        Set userRoles = new HashSet();
//
//        for(int i=0; userRoleAttributes != null && i < userRoleAttributes.length; i++) {
//            Attribute roleAttribute = userAttributes.get(userRoleAttributes[i]);
//
//            addAttributeValuesToRoleSet(roleAttribute, userRoles);
//        }
//
//        return userRoles;
//    }


    public Set getGroupMembershipRoles(String userDn, String username) {
        Set authorities = new HashSet();

        if (getGroupSearchBase() == null) {
            return authorities;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Searching for roles for user '" + username + "', DN = " + "'" + userDn + "', with filter "
                    + groupSearchFilter + " in search base '" + getGroupSearchBase() + "'");
        }

        Set userRoles = ldapTemplate.searchForSingleAttributeValues(getGroupSearchBase(), groupSearchFilter,
                new String[]{userDn, username}, groupRoleAttribute);

        if (logger.isDebugEnabled()) {
            logger.debug("Roles from search: " + userRoles);
        }

        Iterator it = userRoles.iterator();

        while (it.hasNext()) {
            String role = (String) it.next();

            if (convertToUpperCase) {
                role = role.toUpperCase();
            }

            authorities.add(new GrantedAuthorityImpl(rolePrefix + role));
        }

        return authorities;
    }

    /**
     * Searches for groups the user is a member of.
     *
     * @param userDn         the user's distinguished name.
     * @param userAttributes the retrieved user's attributes (unused by default).
     * @return the set of roles obtained from a group membership search, or null if <tt>groupSearchBase</tt> has been
     *         set.
     * @deprecated Subclasses should implement <tt>getAdditionalRoles</tt> instead.
     */
    protected Set getGroupMembershipRoles(String userDn, Attributes userAttributes) {
        return new HashSet();
    }

    protected InitialDirContextFactory getInitialDirContextFactory() {
        return initialDirContextFactory;
    }

    /**
     * Set the {@link InitialDirContextFactory}
     *
     * @param initialDirContextFactory supplies the contexts used to search for user roles.
     */
    private void setInitialDirContextFactory(InitialDirContextFactory initialDirContextFactory) {
        Assert.notNull(initialDirContextFactory, "InitialDirContextFactory must not be null");
        this.initialDirContextFactory = initialDirContextFactory;

        ldapTemplate = new LdapTemplate(initialDirContextFactory);
        ldapTemplate.setSearchControls(searchControls);
    }

    /**
     * Set the group search base (name to search under)
     *
     * @param groupSearchBase if this is an empty string the search will be performed from the root DN of the context
     *                        factory.
     */
    private void setGroupSearchBase(String groupSearchBase) {
        Assert.notNull(groupSearchBase, "The groupSearchBase (name to search under), must not be null.");
        this.groupSearchBase = groupSearchBase;
        if (groupSearchBase.length() == 0) {
            logger.info("groupSearchBase is empty. Searches will be performed from the root: "
                    + getInitialDirContextFactory().getRootDn());
        }
    }

    private String getGroupSearchBase() {
        return groupSearchBase;
    }

    public void setConvertToUpperCase(boolean convertToUpperCase) {
        this.convertToUpperCase = convertToUpperCase;
    }

    /**
     * The default role which will be assigned to all users.
     *
     * @param defaultRole the role name, including any desired prefix.
     */
    public void setDefaultRole(String defaultRole) {
        Assert.notNull(defaultRole, "The defaultRole property cannot be set to null");
        this.defaultRole = new GrantedAuthorityImpl(defaultRole);
    }

    public void setGroupRoleAttribute(String groupRoleAttribute) {
        Assert.notNull(groupRoleAttribute, "groupRoleAttribute must not be null");
        this.groupRoleAttribute = groupRoleAttribute;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        Assert.notNull(groupSearchFilter, "groupSearchFilter must not be null");
        this.groupSearchFilter = groupSearchFilter;
    }

    public void setRolePrefix(String rolePrefix) {
        Assert.notNull(rolePrefix, "rolePrefix must not be null");
        this.rolePrefix = rolePrefix;
    }

    /**
     * If set to true, a subtree scope search will be performed. If false a single-level search is used.
     *
     * @param searchSubtree set to true to enable searching of the entire tree below the <tt>groupSearchBase</tt>.
     */
    public void setSearchSubtree(boolean searchSubtree) {
        int searchScope = searchSubtree ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE;
        searchControls.setSearchScope(searchScope);
    }
}
