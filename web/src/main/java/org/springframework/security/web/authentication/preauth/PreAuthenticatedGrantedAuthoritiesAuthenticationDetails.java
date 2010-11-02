package org.springframework.security.web.authentication.preauth;

import java.util.*;

import org.springframework.security.authentication.AuthenticationDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.MutableGrantedAuthoritiesContainer;
import org.springframework.util.Assert;

/**
 * This AuthenticationDetails implementation allows for storing a list of
 * pre-authenticated Granted Authorities.
 *
 * @author Ruud Senden
 * @since 2.0
 */
@Deprecated
public class PreAuthenticatedGrantedAuthoritiesAuthenticationDetails extends AuthenticationDetails implements
        MutableGrantedAuthoritiesContainer {
    public static final long serialVersionUID = 1L;

    private List<GrantedAuthority> preAuthenticatedGrantedAuthorities = null;

    public PreAuthenticatedGrantedAuthoritiesAuthenticationDetails(Object context) {
        super(context);
    }

    /**
     *
     * @see org.springframework.security.core.authority.GrantedAuthoritiesContainer#getGrantedAuthorities()
     */
    public List<GrantedAuthority> getGrantedAuthorities() {
        Assert.notNull(preAuthenticatedGrantedAuthorities, "Pre-authenticated granted authorities have not been set");

        return preAuthenticatedGrantedAuthorities;
    }

    /**
     * @see MutableGrantedAuthoritiesContainer#setGrantedAuthorities(Collection)
     */
    public void setGrantedAuthorities(Collection<? extends GrantedAuthority> aJ2eeBasedGrantedAuthorities) {
        List<GrantedAuthority> temp = new ArrayList<GrantedAuthority>(aJ2eeBasedGrantedAuthorities.size());
        temp.addAll(aJ2eeBasedGrantedAuthorities);
        this.preAuthenticatedGrantedAuthorities = Collections.unmodifiableList(temp);
    }

    /**
     * @return The String representation of this object.
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append("; ");
        sb.append("preAuthenticatedGrantedAuthorities: ").append(preAuthenticatedGrantedAuthorities);
        return sb.toString();
    }
}
