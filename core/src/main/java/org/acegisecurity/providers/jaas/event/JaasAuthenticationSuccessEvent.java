package net.sf.acegisecurity.providers.jaas.event;

import net.sf.acegisecurity.Authentication;

/**
 * Fired by the {@link net.sf.acegisecurity.providers.jaas.JaasAuthenticationProvider JaasAuthenticationProvider} after
 * successfully logging the user into the LoginContext, handling all callbacks, and calling all AuthorityGranters.
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JaasAuthenticationSuccessEvent extends JaasAuthenticationEvent {

    public JaasAuthenticationSuccessEvent(Authentication auth) {
        super(auth);
    }

}
