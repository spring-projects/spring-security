package org.springframework.security.access.vote;

import static org.junit.Assert.*;

import java.util.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.util.MethodInvocationUtils;

/**
 *
 * @author Luke Taylor
 */
public class AbstractAclVoterTests {
    private AbstractAclVoter voter = new AbstractAclVoter() {
        public boolean supports(ConfigAttribute attribute) {
            return false;
        }
        public int vote(Authentication authentication, MethodInvocation object, Collection<ConfigAttribute> attributes) {
            return 0;
        }
    };

    @Test
    public void supportsMethodInvocations() throws Exception {
        assertTrue(voter.supports(MethodInvocation.class));
        assertFalse(voter.supports(String.class));
    }

    @Test
    public void expectedDomainObjectArgumentIsReturnedFromMethodInvocation() throws Exception {
        voter.setProcessDomainObjectClass(String.class);
        MethodInvocation mi = MethodInvocationUtils.create(new TestClass(), "methodTakingAString", "The Argument");
        assertEquals("The Argument", voter.getDomainObjectInstance(mi));
    }

    @Test
    public void correctArgumentIsSelectedFromMultipleArgs() throws Exception {
        voter.setProcessDomainObjectClass(String.class);
        MethodInvocation mi = MethodInvocationUtils.create(new TestClass(),
                "methodTakingAListAndAString", new ArrayList<Object>(), "The Argument");
        assertEquals("The Argument", voter.getDomainObjectInstance(mi));
    }

    @SuppressWarnings("unused")
    private static class TestClass {
        public void methodTakingAString(String arg) {
        }

        public void methodTaking2Strings(String arg1, String arg2) {
        }

        public void methodTakingAListAndAString(ArrayList<Object> arg1, String arg2) {
        }
    }

}
