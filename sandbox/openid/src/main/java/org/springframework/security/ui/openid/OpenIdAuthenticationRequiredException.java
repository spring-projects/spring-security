package org.springframework.security.ui.openid;

import org.springframework.security.AuthenticationException;

/**
 * @author Ray Krueger
 */
public class OpenIdAuthenticationRequiredException extends AuthenticationException {

    private final String claimedIdentity;

    public OpenIdAuthenticationRequiredException(String msg, String claimedIdentity) {
        super(msg);
        this.claimedIdentity = claimedIdentity;
    }

    public String getClaimedIdentity() {
        return claimedIdentity;
    }
}
