package net.sf.acegisecurity.providers.jaas;

import java.security.Principal;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class TestAuthorityGranter implements AuthorityGranter {
    public String grant(Principal principal) {
        String role = null;
        if (principal.getName().equals("TEST_PRINCIPAL"))
            role = "ROLE_TEST";
        return role;
    }
}
