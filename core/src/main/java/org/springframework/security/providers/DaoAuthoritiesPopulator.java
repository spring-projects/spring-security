package org.springframework.security.providers;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.AuthenticationException;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * Populates the CAS authorities via an {@link org.springframework.security.userdetails.UserDetailsService}.<P>The additional information (username,
 * password, enabled status etc)  an <code>AuthenticationDao</code> implementation provides about  a <code>User</code>
 * is ignored. Only the <code>GrantedAuthority</code>s are relevant to this class.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoAuthoritiesPopulator implements AuthoritiesPopulator, InitializingBean {
    //~ Instance fields ================================================================================================

    private UserDetailsService userDetailsService;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");
    }

    public UserDetails getUserDetails(String casUserId)
        throws AuthenticationException {
        return this.userDetailsService.loadUserByUsername(casUserId);
    }

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
