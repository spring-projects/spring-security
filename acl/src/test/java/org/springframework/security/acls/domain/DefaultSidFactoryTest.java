package org.springframework.security.acls.domain;

import org.junit.Test;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author stanislav bashkirtsev
 */
public class DefaultSidFactoryTest {
    DefaultSidFactory sut = new DefaultSidFactory();

    @Test
    public void testCreate_principal() throws Exception {
        Sid sid = sut.create("sid", true);
        assertTrue(sid instanceof PrincipalSid);
        assertEquals("sid", sid.getSidId());
    }

    @Test
    public void testCreate_grantedAuthority() throws Exception {
        Sid sid = sut.create("sid", false);
        assertTrue((sid instanceof GrantedAuthoritySid));
        assertEquals("sid", sid.getSidId());
    }

    @Test
    public void testCreatePrincipal_anonymous() throws Exception {
        Authentication authentication = new AnonymousAuthenticationToken("key", "a", Arrays.asList(new SimpleGrantedAuthority("ROLE")));
        Sid principal = sut.createPrincipal(authentication);
        assertTrue(principal instanceof PrincipalSid);
        assertEquals("a", principal.getSidId());
    }

    @Test
    public void testCreatePrincipal() throws Exception {
        Authentication authentication = new UsernamePasswordAuthenticationToken("name", "credentials");
        Sid principal = sut.createPrincipal(authentication);
        assertTrue(principal instanceof PrincipalSid);
        assertEquals("name", principal.getSidId());
    }

    @Test
    public void testCreateGrantedAuthorities() throws Exception {
        List<? extends Sid> sids = sut.createGrantedAuthorities(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        assertEquals(1, sids.size());
        assertTrue(sids.get(0) instanceof GrantedAuthoritySid);
        assertEquals("ROLE_USER", sids.get(0).getSidId());
    }

    @Test
    public void testCreateGrantedAuthorities_withEmptyList() throws Exception {
        List<? extends Sid> sids = sut.createGrantedAuthorities(new ArrayList<GrantedAuthority>());
        assertTrue(sids.isEmpty());
    }
}
