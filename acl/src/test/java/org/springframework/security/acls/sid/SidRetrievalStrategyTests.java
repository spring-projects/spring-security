package org.springframework.security.acls.sid;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Test;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Tests for {@link SidRetrievalStrategyImpl}
 *
 * @author Andrei Stefan
 * @author Luke Taylor
 */
@SuppressWarnings("unchecked")
public class SidRetrievalStrategyTests {
    Authentication authentication = new TestingAuthenticationToken("scott", "password", "A", "B", "C");

    //~ Methods ========================================================================================================

    @Test
    public void correctSidsAreRetrieved() throws Exception {
        SidRetrievalStrategy retrStrategy = new SidRetrievalStrategyImpl();
        List<Sid> sids = retrStrategy.getSids(authentication);

        assertNotNull(sids);
        assertEquals(4, sids.size());
        assertNotNull(sids.get(0));
        assertTrue(sids.get(0) instanceof PrincipalSid);

        for (int i = 1; i < sids.size(); i++) {
            assertTrue(sids.get(i) instanceof GrantedAuthoritySid);
        }

        assertEquals("scott", ((PrincipalSid) sids.get(0)).getPrincipal());
        assertEquals("A", ((GrantedAuthoritySid) sids.get(1)).getGrantedAuthority());
        assertEquals("B", ((GrantedAuthoritySid) sids.get(2)).getGrantedAuthority());
        assertEquals("C", ((GrantedAuthoritySid) sids.get(3)).getGrantedAuthority());
    }

    @Test
    public void roleHierarchyIsUsedWhenSet() throws Exception {
        RoleHierarchy rh =  mock(RoleHierarchy.class);
        List<GrantedAuthority> rhAuthorities = AuthorityUtils.createAuthorityList("D");
        when(rh.getReachableGrantedAuthorities(anyList())).thenReturn(rhAuthorities);
        SidRetrievalStrategy strat = new SidRetrievalStrategyImpl(rh);

        List<Sid> sids = strat.getSids(authentication);
        assertEquals(2, sids.size());
        assertNotNull(sids.get(0));
        assertTrue(sids.get(0) instanceof PrincipalSid);
        assertEquals("D", ((GrantedAuthoritySid) sids.get(1)).getGrantedAuthority());
    }
}
