package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.providers.jaas.AuthorityGranter;

import java.security.Principal;

/**
 * Insert comments here...
 * <br>
 * User: raykrueger@users.sourceforge.net<br>
 * Date: Jul 16, 2004<br>
 */
public class TestAuthorityGranter implements AuthorityGranter {
    public String grant(Principal principal) {
        if (principal.getName().equals("TEST_PRINCIPAL"))
            return "ROLE_TEST";
        return null;
    }
}
