package net.sf.acegisecurity.providers.jaas;

import java.security.Principal;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public interface AuthorityGranter {
    public String grant(Principal principal);
}
