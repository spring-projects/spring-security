/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.dao.ldap;

import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.dao.PasswordAuthenticationDao;
import net.sf.acegisecurity.providers.dao.User;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;


/**
 * This is an example <code>PasswordAuthenticationDao</code> implementation
 * using LDAP service for user authentication.
 *
 * @author Karel Miarka
 * @author Daniel Miller
 */
public class LdapPasswordAuthenticationDao implements PasswordAuthenticationDao {
    //~ Static fields/initializers =============================================

    public static final String BAD_CREDENTIALS_EXCEPTION_MESSAGE = "Invalid username, password or context";
    private static final transient Log log = LogFactory.getLog(LdapPasswordAuthenticationDao.class);

    //~ Instance fields ========================================================

    private String host;
    private String rootContext;
    private String userContext = "CN=Users";
    private String[] rolesAttributes = {"memberOf"};
    private int port = 389;

    //~ Methods ================================================================

    /**
     * Set hostname or IP address of the host running LDAP server.
     *
     * @param hostname DOCUMENT ME!
     */
    public void setHost(String hostname) {
        this.host = hostname;
    }

    /**
     * Set the port on which is running the LDAP server. <br>Default value: 389
     *
     * @param port DOCUMENT ME!
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Set the name of user object's attribute(s) which contains the list of
     * user's role names. The role is converted to upper case and a "ROLE_"
     * prefix is added when <code>GrantedAuthority</code> is created. Default
     * value: { "memberOf" }.
     *
     * @param rolesAttributes DOCUMENT ME!
     */
    public void setRolesAttributes(String[] rolesAttributes) {
        this.rolesAttributes = rolesAttributes;
    }

    /**
     * Set the root context to which you attempt to log in. <br>
     * For example: DC=yourdomain,DC=com
     *
     * @param rootContext DOCUMENT ME!
     */
    public void setRootContext(String rootContext) {
        this.rootContext = rootContext;
    }

    /**
     * Set the context in which all users reside relative to the root context. <br>
     * Defalut value: "CN=Users"
     *
     * @param userContext DOCUMENT ME!
     */
    public void setUserContext(String userContext) {
        this.userContext = userContext;
    }

    public UserDetails loadUserByUsernameAndPassword(String username,
        String password) throws DataAccessException, BadCredentialsException {
        if ((password == null) || (password.length() == 0)) {
            throw new BadCredentialsException("Empty password");
        }

        Hashtable env = new Hashtable(11);

        env.put(Context.INITIAL_CONTEXT_FACTORY,
            "com.sun.jndi.ldap.LdapCtxFactory");

        StringBuffer providerUrl = new StringBuffer();
        providerUrl.append("ldap://");
        providerUrl.append(this.host);
        providerUrl.append(":");
        providerUrl.append(this.port);
        providerUrl.append("/");
        providerUrl.append(this.rootContext);

        env.put(Context.PROVIDER_URL, providerUrl.toString());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, getUserPrincipal(username));
        env.put(Context.SECURITY_CREDENTIALS, password);

        try {
            if (log.isDebugEnabled()) {
                log.debug("Connecting to " + providerUrl + " as "
                    + getUserPrincipal(username));
            }

            DirContext ctx = new InitialDirContext(env);

            String[] attrIDs = getRolesAttributeNames();
            Collection roles = getRolesFromContext(ctx, userContext, username,
                    attrIDs);
            ctx.close();

            if (roles.isEmpty()) {
                throw new BadCredentialsException("The user has no granted "
                    + "authorities or the rolesAttribute is invalid");
            }

            String[] ldapRoles = (String[]) roles.toArray(new String[] {});

            return new User(username, password, true,
                getGrantedAuthorities(ldapRoles));
        } catch (AuthenticationException ex) {
            throw new BadCredentialsException(BAD_CREDENTIALS_EXCEPTION_MESSAGE,
                ex);
        } catch (CommunicationException ex) {
            throw new DataAccessResourceFailureException(ex.getRootCause()
                                                           .getMessage(), ex);
        } catch (NamingException ex) {
            throw new DataAccessResourceFailureException(ex.getMessage(), ex);
        }
    }

    /**
     * Get an array <code>GrantedAuthorities</code> given the list of roles
     * obtained from the LDAP context. Delegates to
     * <code>getGrantedAuthority(String ldapRole)</code>. This function may be
     * overridden in a subclass.
     *
     * @param ldapRoles DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected GrantedAuthority[] getGrantedAuthorities(String[] ldapRoles) {
        GrantedAuthority[] grantedAuthorities = new GrantedAuthority[ldapRoles.length];

        for (int i = 0; i < ldapRoles.length; i++) {
            grantedAuthorities[i] = getGrantedAuthority(ldapRoles[i]);
        }

        return grantedAuthorities;
    }

    /**
     * Get a <code>GrantedAuthority</code> given a role obtained from the LDAP
     * context. If found in the LDAP role, the following characters are
     * converted to underscore: ',' (comma), '=' (equals), ' ' (space) This
     * function may be overridden in a subclass.
     *
     * @param ldapRole DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected GrantedAuthority getGrantedAuthority(String ldapRole) {
        GrantedAuthority ga = new GrantedAuthorityImpl("ROLE_"
                + ldapRole.toUpperCase());

        if (log.isDebugEnabled()) {
            log.debug("GrantedAuthority: " + ga);
        }

        return ga;
    }

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     *
     * @return Return true if the given name is a role attribute.
     */
    protected boolean isRoleAttribute(String name) {
        if (name != null) {
            for (int i = 0; i < rolesAttributes.length; i++) {
                if (name.equals(rolesAttributes[i])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get the attributes to that contain role information. This function may
     * be overridden in a subclass.
     *
     * @return DOCUMENT ME!
     */
    protected String[] getRolesAttributeNames() {
        return rolesAttributes;
    }

    protected Collection getRolesFromContext(DirContext ctx,
        String userContext, String username, String[] roleAttributes)
        throws NamingException {
        List roles = new ArrayList();

        if (log.isDebugEnabled()) {
            String rolesString = "";

            for (int i = 0; i < roleAttributes.length; i++) {
                rolesString += (", " + roleAttributes[i]);
            }

            log.debug("Searching user context '" + userContext + "' for roles "
                + "attributes: " + rolesString.substring(1));
        }

        NamingEnumeration answer = ctx.search(userContext,
                getUsernameAttributes(username), roleAttributes);

        while (answer.hasMore()) {
            SearchResult sr = (SearchResult) answer.next();
            NamingEnumeration attrs = sr.getAttributes().getAll();

            while (attrs.hasMore()) {
                Attribute attr = (Attribute) attrs.next();

                if (isRoleAttribute(attr.getID())) {
                    NamingEnumeration rolesAttr = attr.getAll();

                    while (rolesAttr.hasMore()) {
                        String role = (String) rolesAttr.next();
                        roles.add(role);

                        if (log.isDebugEnabled()) {
                            log.debug("Role read: " + attr.getID() + "=" + role);
                        }
                    }
                }
            }
        }

        return roles;
    }

    /**
     * Get the <code>Context.SECURITY_PRINCIPAL</code> for the given username
     * string. This implementation returns a string composed of the following:
     * &lt;usernamePrefix&gt;&lt;username&gt;&lt;usernameSufix. This function
     * may be overridden in a subclass.
     *
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected String getUserPrincipal(String username) {
        StringBuffer principal = new StringBuffer();
        principal.append("CN=");
        principal.append(username);
        principal.append(",");
        principal.append(this.userContext);
        principal.append(",");
        principal.append(this.rootContext);

        return principal.toString();
    }

    /**
     * Get the attribute(s) to match when searching for the user object. This
     * implementation returns a "distinguishedName" attribute with the value
     * returned by <code>getUserPrincipal(username)</code>. A subclass may
     * customize this behavior by overriding <code>getUserPrincipal</code>
     * and/or <code>getUsernameAttributes</code>.
     *
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected Attributes getUsernameAttributes(String username) {
        Attributes matchAttrs = new BasicAttributes(true); // ignore case
        matchAttrs.put(new BasicAttribute("distinguishedName",
                getUserPrincipal(username)));

        return matchAttrs;
    }
}
