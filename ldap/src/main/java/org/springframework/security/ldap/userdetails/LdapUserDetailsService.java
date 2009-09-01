package org.springframework.security.ldap.userdetails;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.authentication.NullLdapAuthoritiesPopulator;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.util.Assert;

/**
 * LDAP implementation of UserDetailsService based around an {@link LdapUserSearch}
 * and an {@link LdapAuthoritiesPopulator}. The final <tt>UserDetails</tt> object
 * returned from <tt>loadUserByUsername</tt> is created by the configured <tt>UserDetailsContextMapper</tt>.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsService implements UserDetailsService {
    private LdapUserSearch userSearch;
    private LdapAuthoritiesPopulator authoritiesPopulator;
    private UserDetailsContextMapper userDetailsMapper = new LdapUserDetailsMapper();

    public LdapUserDetailsService(LdapUserSearch userSearch) {
        this(userSearch, new NullLdapAuthoritiesPopulator());
    }

    public LdapUserDetailsService(LdapUserSearch userSearch, LdapAuthoritiesPopulator authoritiesPopulator) {
        Assert.notNull(userSearch, "userSearch must not be null");
        Assert.notNull(authoritiesPopulator, "authoritiesPopulator must not be null");
        this.userSearch = userSearch;
        this.authoritiesPopulator = authoritiesPopulator;
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        DirContextOperations userData = userSearch.searchForUser(username);

        return userDetailsMapper.mapUserFromContext(userData, username,
                authoritiesPopulator.getGrantedAuthorities(userData, username));
    }

    public void setUserDetailsMapper(UserDetailsContextMapper userDetailsMapper) {
        Assert.notNull(userDetailsMapper, "userDetailsMapper must not be null");
        this.userDetailsMapper = userDetailsMapper;
    }
}
