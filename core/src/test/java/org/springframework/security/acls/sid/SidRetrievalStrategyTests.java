package org.springframework.security.acls.sid;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.providers.TestingAuthenticationToken;

/**
 * Tests for {@link SidRetrievalStrategyImpl}
 * 
 * @author Andrei Stefan
 */
public class SidRetrievalStrategyTests extends TestCase {

    //~ Methods ========================================================================================================

    public void testSidsRetrieval() throws Exception {
        Authentication authentication = new TestingAuthenticationToken("scott", "password", new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl("ROLE_2"), new GrantedAuthorityImpl("ROLE_3") });
        SidRetrievalStrategy retrStrategy = new SidRetrievalStrategyImpl();
        Sid[] sids = retrStrategy.getSids(authentication);

        Assert.assertNotNull(sids);
        Assert.assertEquals(4, sids.length);
        Assert.assertNotNull(sids[0]);

        Assert.assertTrue(PrincipalSid.class.isAssignableFrom(sids[0].getClass()));
        for (int i = 1; i < sids.length; i++) {
            Sid sid = sids[i];
            Assert.assertTrue(GrantedAuthoritySid.class.isAssignableFrom(sid.getClass()));
        }

        Assert.assertEquals("scott", ((PrincipalSid) sids[0]).getPrincipal());
        Assert.assertEquals("ROLE_1", ((GrantedAuthoritySid) sids[1]).getGrantedAuthority());
        Assert.assertEquals("ROLE_2", ((GrantedAuthoritySid) sids[2]).getGrantedAuthority());
        Assert.assertEquals("ROLE_3", ((GrantedAuthoritySid) sids[3]).getGrantedAuthority());
    }
}
