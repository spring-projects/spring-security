package net.sf.acegisecurity.providers.jaas;

import java.security.Principal;

/**
 * Insert comments here...
 * <br>
 * User: raykrueger@users.sourceforge.net<br>
 * Date: Jul 15, 2004<br>
 */
public interface AuthorityGranter {
    public String grant(Principal principal);
}
