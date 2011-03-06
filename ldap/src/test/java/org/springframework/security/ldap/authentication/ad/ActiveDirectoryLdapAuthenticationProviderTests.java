package org.springframework.security.ldap.authentication.ad;

import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Luke Taylor
 */
public class ActiveDirectoryLdapAuthenticationProviderTests {

    @Test
    public void simpleAuthenticationWithIsSucessful() throws Exception {
        ActiveDirectoryLdapAuthenticationProvider provider =
                new ActiveDirectoryLdapAuthenticationProvider(null, "ldap://192.168.1.200/");

        Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("luke@fenetres.monkeymachine.eu","p!ssw0rd"));

        assertEquals(1, result.getAuthorities().size());
        assertTrue(result.getAuthorities().contains(new SimpleGrantedAuthority("blah")));
    }
}
