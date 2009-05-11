package org.springframework.security.acls.sid;

import java.util.List;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Tests for {@link SidRetrievalStrategyImpl}
 *
 * @author Andrei Stefan
 */
public class SidRetrievalStrategyTests extends TestCase {

    //~ Methods ========================================================================================================

    public void testSidsRetrieval() throws Exception {
        Authentication authentication = new TestingAuthenticationToken("scott", "password", "ROLE_1", "ROLE_2", "ROLE_3");
        SidRetrievalStrategy retrStrategy = new SidRetrievalStrategyImpl();
        List<Sid> sids = retrStrategy.getSids(authentication);

        assertNotNull(sids);
        assertEquals(4, sids.size());
        assertNotNull(sids.get(0));
        assertTrue(sids.get(0) instanceof PrincipalSid);

        for (int i = 1; i < sids.size(); i++) {
            assertTrue(sids.get(i) instanceof GrantedAuthoritySid);
        }

        Assert.assertEquals("scott", ((PrincipalSid) sids.get(0)).getPrincipal());
        Assert.assertEquals("ROLE_1", ((GrantedAuthoritySid) sids.get(1)).getGrantedAuthority());
        Assert.assertEquals("ROLE_2", ((GrantedAuthoritySid) sids.get(2)).getGrantedAuthority());
        Assert.assertEquals("ROLE_3", ((GrantedAuthoritySid) sids.get(3)).getGrantedAuthority());
    }
}
