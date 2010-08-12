package org.springframework.security.web.authentication.preauth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthoritiesContainer;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This WebAuthenticationDetails implementation allows for storing a list of
 * pre-authenticated Granted Authorities.
 *
 * @author Ruud Senden
 * @author Luke Taylor
 * @since 2.0
 */
public class PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails extends WebAuthenticationDetails implements
        GrantedAuthoritiesContainer {

    private final List<GrantedAuthority> authorities;

    public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(HttpServletRequest request,
            List<GrantedAuthority> authorities) {
        super(request);

        List<GrantedAuthority> temp = new ArrayList<GrantedAuthority>(authorities.size());
        temp.addAll(authorities);
        this.authorities = Collections.unmodifiableList(temp);
    }

    public List<GrantedAuthority> getGrantedAuthorities() {
        return authorities;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append("; ");
        sb.append(authorities);
        return sb.toString();
    }
}
