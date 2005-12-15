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

package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.providers.ldap.LdapUserDetails;
import org.acegisecurity.providers.ldap.LdapUtils;
import org.acegisecurity.providers.encoding.PasswordEncoder;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.DirContext;
import javax.naming.directory.Attribute;

/**
 * An {@link org.acegisecurity.providers.ldap.LdapAuthenticator LdapAuthenticator}
 * which compares the login password with the value stored in the directory.
 * <p>
 * This can be achieved either by retrieving the password attribute for the user
 * and comparing it locally, or by peforming an LDAP "compare" operation.
 * If the password attribute (default "userPassword") is found in the retrieved
 * attributes it will be compared locally. If not, the remote comparison will be
 * attempted.
 * </p>
 * <p>
 * If passwords are stored in digest form in the repository, then a suitable
 * {@link PasswordEncoder} implementation must be supplied. By default, passwords are
 * encoded using the {@link LdapShaPasswordEncoder}.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class PasswordComparisonAuthenticator extends AbstractLdapAuthenticator {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(PasswordComparisonAuthenticator.class);

    private static final String[] NO_ATTRS = new String[0];

    //~ Instance fields ========================================================

    private String passwordAttributeName = "userPassword";

    private String passwordCompareFilter = "(userPassword={0})";

    private PasswordEncoder passwordEncoder = new LdapShaPasswordEncoder();

    //~ Methods ================================================================

    public LdapUserDetails authenticate(String username, String password) {

        // locate the user and check the password
        String userDn = getUserDn(username);
        LdapUserDetails user = null;

        DirContext ctx = getInitialDirContextFactory().newInitialDirContext();

        try {
            if(userDn != null) {
                String relativeName = LdapUtils.getRelativeName(userDn, ctx);

                user = new LdapUserDetails(userDn,
                        ctx.getAttributes(relativeName, getUserAttributes()));
            }

            if(user == null && getUserSearch() != null) {
                user = getUserSearch().searchForUser(username);
            }

            if(user == null) {
                throw new UsernameNotFoundException(username);
            }

            Attribute passwordAttribute = user.getAttributes().get(passwordAttributeName);

            if(passwordAttribute != null) {
                Object retrievedPassword = passwordAttribute.get();

                if(!(retrievedPassword instanceof String)) {
                    // Assume it's binary
                    retrievedPassword = new String((byte[])retrievedPassword);
                }

                if(!verifyPassword(password, (String)retrievedPassword)) {
                    throw new BadCredentialsException("Invalid password.");
                }

            } else {

                doPasswordCompare(ctx, user.getRelativeName(ctx), password);
            }

            return user;
        } catch(NamingException ne) {
            throw new BadCredentialsException("Authentication failed due to exception ", ne);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }

    /**
     * Allows the use of both simple and hashed passwords in the directory.
     */
    private boolean verifyPassword(String password, String ldapPassword) {
        if(ldapPassword.equals(password)) {
            return true;
        }

        if(passwordEncoder.isPasswordValid(ldapPassword, password, null)) {
            return true;
        }

        return false;
    }

    private void doPasswordCompare(DirContext ctx, String name, String password) throws NamingException {
        if(logger.isDebugEnabled()) {
            logger.debug("Performing LDAP compare of password for " + name);
        }

        password = passwordEncoder.encodePassword(password, null);
        byte[] passwordBytes = LdapUtils.getUtf8Bytes(password);

        SearchControls ctls = new SearchControls();
        ctls.setReturningAttributes(NO_ATTRS);
        ctls.setSearchScope(SearchControls.OBJECT_SCOPE);

        NamingEnumeration results = ctx.search(name, passwordCompareFilter,
                new Object[]{passwordBytes}, ctls);

        if(!results.hasMore()) {
            throw new BadCredentialsException("Password comparison failed");
        }
    }

    public void setPasswordAttributeName(String passwordAttribute) {
        Assert.hasLength(passwordAttribute, "passwordAttribute must not be empty or null");
        this.passwordAttributeName = passwordAttribute;
        this.passwordCompareFilter = "(" + passwordAttributeName + "={0})";
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        Assert.notNull(passwordEncoder, "Password Encoder must not be null.");
        this.passwordEncoder = passwordEncoder;
    }
}
