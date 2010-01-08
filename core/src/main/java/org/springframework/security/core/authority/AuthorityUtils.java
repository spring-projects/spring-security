package org.springframework.security.core.authority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

/**
 * Utility method for manipulating <tt>GrantedAuthority</tt> collections etc.
 * <p>
 * Mainly intended for internal use.
 *
 * @author Luke Taylor
 */
public abstract class AuthorityUtils {
    public static final List<GrantedAuthority> NO_AUTHORITIES = Collections.emptyList();

    /**
     * Creates a array of GrantedAuthority objects from a comma-separated string
     * representation (e.g. "ROLE_A, ROLE_B, ROLE_C").
     *
     * @param authorityString the comma-separated string
     * @return the authorities created by tokenizing the string
     */
    public static List<GrantedAuthority> commaSeparatedStringToAuthorityList(String authorityString) {
        return createAuthorityList(StringUtils.tokenizeToStringArray(authorityString, ","));
    }

    /**
     * Converts an array of GrantedAuthority objects to a Set.
     * @return a Set of the Strings obtained from each call to GrantedAuthority.getAuthority()
     */
    public static Set<String> authorityListToSet(Collection<GrantedAuthority> userAuthorities) {
        Set<String> set = new HashSet<String>(userAuthorities.size());

        for (GrantedAuthority authority: userAuthorities) {
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
