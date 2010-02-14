/**
 * The LDAP authentication provider package. Interfaces are provided for
 * both authentication and retrieval of user roles from an LDAP server.
 * <p>
 * The main provider class is <tt>LdapAuthenticationProvider</tt>.
 * This is configured with an <tt>LdapAuthenticator</tt> instance and
 * an <tt>LdapAuthoritiesPopulator</tt>. The latter is used to obtain the
 * list of roles for the user.
 */
package org.springframework.security.ldap.authentication;

