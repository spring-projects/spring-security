package org.springframework.security.ldap;

import org.junit.Test;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultSpringSecurityContextSourceTests {

    @Test
    public void instantiationSucceeds() {
        new DefaultSpringSecurityContextSource("ldap://blah:789/dc=springframework,dc=org");
    }

    @Test
    public void supportsSpacesInUrl() {
    	new DefaultSpringSecurityContextSource("ldap://myhost:10389/dc=spring%20framework,dc=org");
    }
    
}
