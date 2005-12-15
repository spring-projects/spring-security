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

import org.acegisecurity.providers.ldap.LdapAuthenticator;
import org.acegisecurity.providers.ldap.InitialDirContextFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.text.MessageFormat;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractLdapAuthenticator implements LdapAuthenticator,
    InitializingBean {

    //~ Instance fields ========================================================

    private String userDnPattern = null;
    private MessageFormat userDnFormat = null;
    private InitialDirContextFactory initialDirContextFactory;
    private LdapUserSearch userSearch;
    private String[] userAttributes = null;

    //~ Methods ================================================================

    /**
     * Returns the DN of the user, worked out from the userDNPattern property.
     * The returned value includes the root DN of the provider
     * URL used to configure the <tt>InitialDirContextfactory</tt>.
     */
    protected String getUserDn(String username) {
        if(userDnFormat == null) {
            return null;
        }

        String rootDn = initialDirContextFactory.getRootDn();
        String userDn;

        synchronized( userDnFormat ) {
            userDn = userDnFormat.format(new String[] {username});
        }

        if(rootDn.length() > 0) {
            userDn = userDn + "," + rootDn;
        }

        return userDn;
    }

    /**
     * Sets the pattern which will be used to supply a DN for the user.
     * The pattern should be the name relative to the root DN.
     * The pattern argument {0} will contain the username.
     * An example would be "cn={0},ou=people".
     */
    public void setUserDnPattern(String dnPattern) {
        this.userDnPattern = dnPattern;
        userDnFormat = null;

        if(dnPattern != null) {
            userDnFormat = new MessageFormat(dnPattern);
        }
    }

    public String[] getUserAttributes() {
        return userAttributes;
    }

    public String getUserDnPattern() {
        return userDnPattern;
    }

    public void setUserSearch(LdapUserSearch userSearch) {
        this.userSearch = userSearch;
    }

    protected LdapUserSearch getUserSearch() {
        return userSearch;
    }

    public void setInitialDirContextFactory(InitialDirContextFactory initialDirContextFactory) {
        this.initialDirContextFactory = initialDirContextFactory;
    }

    /**
     * Sets the user attributes which will be retrieved from the directory.
     * 
     * @param userAttributes
     */
    public void setUserAttributes(String[] userAttributes) {
        this.userAttributes = userAttributes;
    }

    protected InitialDirContextFactory getInitialDirContextFactory() {
        return initialDirContextFactory;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(initialDirContextFactory, "initialDirContextFactory must be supplied.");
        Assert.isTrue(userDnPattern != null || userSearch != null, "Either an LdapUserSearch or DN pattern (or both) must be supplied.");
    }
}
