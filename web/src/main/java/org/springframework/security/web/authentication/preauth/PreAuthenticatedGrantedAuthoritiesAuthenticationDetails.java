package org.springframework.security.web.authentication.preauth;

import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.AuthenticationDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.MutableGrantedAuthoritiesContainer;
import org.springframework.util.Assert;

/**
 * This AuthenticationDetails implementation allows for storing a list of
 * pre-authenticated Granted Authorities.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class PreAuthenticatedGrantedAuthoritiesAuthenticationDetails extends AuthenticationDetails implements
        MutableGrantedAuthoritiesContainer {
    public static final long serialVersionUID = 1L;

    private List<GrantedAuthority> preAuthenticatedGrantedAuthorities = null;

    public PreAuthenticatedGrantedAuthoritiesAuthenticationDetails(Object context) {
        super(context);
    }

    /**
     * @return The String representation of this object.
     */
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString() + "; ");
        sb.append("preAuthenticatedGrantedAuthorities: " + preAuthenticatedGrantedAuthorities);
        return sb.toString();
    }

    /**
     *
     * @see org.springframework.security.core.GrantedAuthoritiesContainer#getGrantedAuthorities()
     */
    public List<GrantedAuthority> getGrantedAuthorities() {
        Assert.notNull(preAuthenticatedGrantedAuthorities, "Pre-authenticated granted authorities have not been set");

        return preAuthenticatedGrantedAuthorities;
    }

    /**
     * @see org.springframework.security.core.MutableGrantedAuthoritiesContainer#setGrantedAuthorities()
     */
    public void setGrantedAuthorities(List<GrantedAuthority> aJ2eeBasedGrantedAuthorities) {
        this.preAuthenticatedGrantedAuthorities = Collections.unmodifiableList(aJ2eeBasedGrantedAuthorities);
    }
}
