package org.springframework.security.util;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.util.StringUtils;

/**
 * @author luke
 * @version $Id$
 */
public abstract class AuthorityUtils {

    /**
     * Creates a array of GrantedAuthority objects from a comma-separated string
     * representation (e.g. "ROLE_A, ROLE_B, ROLE_C").
     *
     * @param authorityString the comma-separated string
     * @return the authorities created by tokenizing the string
     */
    public static GrantedAuthority[] commaSeparatedStringToAuthorityArray(String authorityString) {
        String[] authorityStrings = StringUtils.tokenizeToStringArray(authorityString, ",");
        GrantedAuthority[] authorities = new GrantedAuthority[authorityStrings.length];

        for (int i=0; i < authorityStrings.length; i++) {
            authorities[i] = new GrantedAuthorityImpl(authorityStrings[i]);
        }

        return authorities;
    }


}
