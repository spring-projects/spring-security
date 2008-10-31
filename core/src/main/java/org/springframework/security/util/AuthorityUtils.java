package org.springframework.security.util;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AuthorityUtils {
    public static final List<GrantedAuthority> NO_AUTHORITIES = Collections.EMPTY_LIST;

    /**
     * Returns true if the current user has the specified authority.
     *
     * @param authority the authority to test for (e.g. "ROLE_A").
     * @return true if a GrantedAuthority object with the same string representation as the supplied authority
     * name exists in the current user's list of authorities. False otherwise, or if the user in not authenticated.
     */
    public static boolean userHasAuthority(String authority) {
        List<GrantedAuthority> authorities = getUserAuthorities();

        for (GrantedAuthority grantedAuthority : authorities) {
            if (authority.equals(grantedAuthority.getAuthority())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the authorities of the current user.
     *
     * @return an array containing the current user's authorities (or an empty array if not authenticated), never null.
     */
    private static List<GrantedAuthority> getUserAuthorities() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth.getAuthorities() == null) {
            return NO_AUTHORITIES;
        }

        return auth.getAuthorities();
    }


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

    /**
     * Converts an array of GrantedAuthority objects to a Set.
     * @return a Set of the Strings obtained from each call to GrantedAuthority.getAuthority()
     */
    public static Set authorityArrayToSet(List<GrantedAuthority> authorities) {
        Set set = new HashSet(authorities.size());

        for (GrantedAuthority authority: authorities) {
            set.add(authority.getAuthority());
        }

        return set;
    }

    public static List<GrantedAuthority> createAuthorityList(String... roles) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(roles.length);

        for (int i=0; i < roles.length; i++) {
            authorities.add(new GrantedAuthorityImpl(roles[i]));
        }

        return authorities;
    }
}
