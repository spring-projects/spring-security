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

package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.BadCredentialsException;

import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapTemplate;
import org.acegisecurity.ldap.LdapUtils;

import org.acegisecurity.providers.encoding.PasswordEncoder;

import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;

import java.util.Iterator;


/**
 * An {@link org.acegisecurity.providers.ldap.LdapAuthenticator LdapAuthenticator} which compares the login
 * password with the value stored in the directory.<p>This can be achieved either by retrieving the password
 * attribute for the user and comparing it locally, or by peforming an LDAP "compare" operation. If the password
 * attribute (default "userPassword") is found in the retrieved attributes it will be compared locally. If not, the
 * remote comparison will be attempted.</p>
 *  <p>If passwords are stored in digest form in the repository, then a suitable {@link PasswordEncoder}
 * implementation must be supplied. By default, passwords are encoded using the {@link LdapShaPasswordEncoder}.</p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public final class PasswordComparisonAuthenticator extends AbstractLdapAuthenticator {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(PasswordComparisonAuthenticator.class);

    //~ Instance fields ================================================================================================

    private PasswordEncoder passwordEncoder = new LdapShaPasswordEncoder();
    private String passwordAttributeName = "userPassword";

    //~ Constructors ===================================================================================================

    public PasswordComparisonAuthenticator(InitialDirContextFactory initialDirContextFactory) {
        super(initialDirContextFactory);
    }

    //~ Methods ========================================================================================================

    public LdapUserDetails authenticate(final String username, final String password) {
        // locate the user and check the password
        LdapUserDetails user = null;

        Iterator dns = getUserDns(username).iterator();

        LdapTemplate ldapTemplate = new LdapTemplate(getInitialDirContextFactory());

        while (dns.hasNext() && (user == null)) {
            final String userDn = (String) dns.next();

            if (ldapTemplate.nameExists(userDn)) {
                LdapUserDetailsImpl.Essence userEssence = (LdapUserDetailsImpl.Essence) ldapTemplate.retrieveEntry(userDn,
                        getUserDetailsMapper(), getUserAttributes());
                userEssence.setUsername(username);
                user = userEssence.createUserDetails();
            }
        }

        if ((user == null) && (getUserSearch() != null)) {
            user = getUserSearch().searchForUser(username);
        }

        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        String retrievedPassword = user.getPassword();

        if (retrievedPassword != null) {
            if (!verifyPassword(password, retrievedPassword)) {
                throw new BadCredentialsException(messages.getMessage(
                        "PasswordComparisonAuthenticator.badCredentials", "Bad credentials"));
            }

            return user;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Password attribute wasn't retrieved for user '" + username + "' using mapper "
                + getUserDetailsMapper() + ". Performing LDAP compare of password attribute '" + passwordAttributeName
                + "'");
        }

        String encodedPassword = passwordEncoder.encodePassword(password, null);
        byte[] passwordBytes = LdapUtils.getUtf8Bytes(encodedPassword);

        if (!ldapTemplate.compare(user.getDn(), passwordAttributeName, passwordBytes)) {
            throw new BadCredentialsException(messages.getMessage("PasswordComparisonAuthenticator.badCredentials",
                    "Bad credentials"));
        }

        return user;
    }

    public void setPasswordAttributeName(String passwordAttribute) {
        Assert.hasLength(passwordAttribute, "passwordAttributeName must not be empty or null");
        this.passwordAttributeName = passwordAttribute;
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        Assert.notNull(passwordEncoder, "passwordEncoder must not be null.");
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Allows the use of both simple and hashed passwords in the directory.
     *
     * @param password DOCUMENT ME!
     * @param ldapPassword DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    private boolean verifyPassword(String password, String ldapPassword) {
        if (ldapPassword.equals(password)) {
            return true;
        }

        if (passwordEncoder.isPasswordValid(ldapPassword, password, null)) {
            return true;
        }

        return false;
    }
}
