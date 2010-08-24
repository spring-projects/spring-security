package org.springframework.security.cas.userdetails;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.junit.Test;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author Luke Taylor
 */
public class GrantedAuthorityFromAssertionAttributesUserDetailsServiceTests {

    @Test
    public void correctlyExtractsNamedAttributesFromAssertionAndConvertsThemToAuthorities() {
        GrantedAuthorityFromAssertionAttributesUserDetailsService uds =
                new GrantedAuthorityFromAssertionAttributesUserDetailsService(new String[] {"a", "b", "c", "d"});
        uds.setConvertToUpperCase(false);
        Assertion assertion = mock(Assertion.class);
        AttributePrincipal principal = mock(AttributePrincipal.class);
        Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("a", Arrays.asList("role_a1", "role_a2"));
        attributes.put("b", "role_b");
        attributes.put("c", "role_c");
        attributes.put("d", null);
        attributes.put("someother", "unused");
        when(assertion.getPrincipal()).thenReturn(principal);
        when(principal.getAttributes()).thenReturn(attributes);
        when(principal.getName()).thenReturn("somebody");
        CasAssertionAuthenticationToken token = new CasAssertionAuthenticationToken(assertion, "ticket");
        UserDetails user = uds.loadUserDetails(token);
        Set<String> roles = AuthorityUtils.authorityListToSet(user.getAuthorities());
        assertTrue(roles.size() == 4);
        assertTrue(roles.contains("role_a1"));
        assertTrue(roles.contains("role_a2"));
        assertTrue(roles.contains("role_b"));
        assertTrue(roles.contains("role_c"));
    }
}
