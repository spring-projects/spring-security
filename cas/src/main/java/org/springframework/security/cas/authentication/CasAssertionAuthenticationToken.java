package org.springframework.security.cas.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.jasig.cas.client.validation.Assertion;

import java.util.List;
import java.util.ArrayList;

/**
 * Temporary authentication object needed to load the user details service.
 *
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.0
 */
public final class CasAssertionAuthenticationToken extends AbstractAuthenticationToken {

    private final Assertion assertion;

    private final String ticket;

    public CasAssertionAuthenticationToken(final Assertion assertion, final String ticket) {
        super(new ArrayList<GrantedAuthority>());

        this.assertion = assertion;
        this.ticket = ticket;
    }

    public Object getPrincipal() {
        return this.assertion.getPrincipal().getName();
    }

    public Object getCredentials() {
        return this.ticket;
    }

    public Assertion getAssertion() {
        return this.assertion;
    }
}
