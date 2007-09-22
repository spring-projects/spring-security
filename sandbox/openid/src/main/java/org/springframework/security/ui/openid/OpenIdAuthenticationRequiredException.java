package org.acegisecurity.ui.openid;

import org.acegisecurity.AuthenticationException;

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
