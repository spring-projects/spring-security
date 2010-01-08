package org.springframework.security.ldap;

import org.springframework.ldap.core.DistinguishedName;

/**
 * Constructs an Ldap Distinguished Name from a username.
 *
 * @author Luke Taylor
 */
public interface LdapUsernameToDnMapper {
    DistinguishedName buildDn(String username);
}
