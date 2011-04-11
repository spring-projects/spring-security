package org.springframework.security.ldap.authentication.ad;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import org.junit.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import javax.naming.spi.InitialContextFactory;
import javax.naming.spi.InitialContextFactoryBuilder;
import javax.naming.spi.NamingManager;
import java.util.*;

/**
 * @author Luke Taylor
 */
public class ActiveDirectoryLdapAuthenticationProviderTests {

    @Test
    public void bindPrincipalIsCreatedCorrectly() throws Exception {
        ActiveDirectoryLdapAuthenticationProvider provider =
                new ActiveDirectoryLdapAuthenticationProvider("mydomain.eu", "ldap://192.168.1.200/");
        assertEquals("joe@mydomain.eu", provider.createBindPrincipal("joe"));
        assertEquals("joe@mydomain.eu", provider.createBindPrincipal("joe@mydomain.eu"));
    }

//    @Test
//    public void realAuthenticationIsSucessful() throws Exception {
//        ActiveDirectoryLdapAuthenticationProvider provider =
//                new ActiveDirectoryLdapAuthenticationProvider(null, "ldap://192.168.1.200/");
//
//        provider.setConvertSubErrorCodesToExceptions(true);
//
//        Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("luke@fenetres.monkeymachine.eu","p!ssw0rd"));
//
//        assertEquals(1, result.getAuthorities().size());
//        assertTrue(result.getAuthorities().contains(new SimpleGrantedAuthority("blah")));
//    }
}
