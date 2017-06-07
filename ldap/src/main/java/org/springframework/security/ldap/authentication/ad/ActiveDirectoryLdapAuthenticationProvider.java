/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.ldap.authentication.ad;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * Specialized LDAP authentication provider which uses Active Directory configuration
 * conventions.
 * <p/>
 * It will authenticate using the Active Directory <a
 * href="http://msdn.microsoft.com/en-us/library/ms680857%28VS.85%29.aspx">
 * {@code userPrincipalName}</a> or a custom {@link #setSearchFilter(String) searchFilter}
 * in the form {@code username@domain}. If the username does not already end with the
 * domain name, the {@code userPrincipalName} will be built by appending the configured
 * domain name to the username supplied in the authentication request. If no domain name
 * is configured, it is assumed that the username will always contain the domain name.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Dieter Hubau
 * @since 3.1
 */
public final class ActiveDirectoryLdapAuthenticationProvider extends AbstractActiveDirectoryLdapAuthenticationProvider {

    /**
     * @param domain the domain name (may be null or empty)
     * @param url    an LDAP url (or multiple URLs)
     * @param rootDn the root DN (may be null or empty)
     */
    public ActiveDirectoryLdapAuthenticationProvider(String domain, String url, String rootDn) {
        super(domain, url, rootDn);
    }

    /**
     * @param domain the domain name (may be null or empty)
     * @param url    an LDAP url (or multiple URLs)
     */
    public ActiveDirectoryLdapAuthenticationProvider(String domain, String url) {
        super(domain, url);
    }

    @Override
    protected String createBindPrincipal(final UsernamePasswordAuthenticationToken auth) {
        String username = auth.getName();
        return createBindPrincipal(username);
    }

    @Override
    protected String createSearchPrincipal(final UsernamePasswordAuthenticationToken auth) {
        return createBindPrincipal(auth);
    }

    /**
     * Creates a bind principal string from a given username and the optional domain.
     *
     * @param username username
     * @return bind string containing username and domain
     */
    public String createBindPrincipal(String username) {
        if (domain == null || username.toLowerCase().endsWith(domain)) {
            return username;
        }

        return username + "@" + domain;
    }
}
