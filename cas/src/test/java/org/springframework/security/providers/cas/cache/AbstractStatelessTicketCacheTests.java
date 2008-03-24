package org.springframework.security.providers.cas.cache;

import java.util.ArrayList;
import java.util.List;

import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.providers.cas.CasAuthenticationToken;
import org.springframework.security.userdetails.User;

/**
 * 
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 2.0
 *
 */
public abstract class AbstractStatelessTicketCacheTests {
	
	protected CasAuthenticationToken getToken() {
        List<String> proxyList = new ArrayList<String>();
        proxyList.add("https://localhost/newPortal/j_spring_cas_security_check");

        User user = new User("rod", "password", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
        final Assertion assertion = new AssertionImpl("rod");

        return new CasAuthenticationToken("key", user, "ST-0-ER94xMJmn6pha35CQRoZ",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")}, user,
            assertion);
    }

}
