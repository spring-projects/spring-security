package org.springframework.security.vote;

import static org.junit.Assert.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.aspectj.lang.JoinPoint;
import org.junit.Test;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.MockJoinPoint;
import org.springframework.security.TargetObject;
import org.springframework.security.util.MethodInvocationUtils;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AbstractAclVoterTests {
    private AbstractAclVoter voter = new AbstractAclVoter() {
        public boolean supports(ConfigAttribute attribute) {
            return false;
        }
        public int vote(Authentication authentication, Object object, List<ConfigAttribute> attributes) {
            return 0;
        }
    };

    @Test
    public void supportsMethodInvocationsAndJoinPoints() throws Exception {
        assertTrue(voter.supports(MethodInvocation.class));
        assertTrue(voter.supports(JoinPoint.class));
        assertFalse(voter.supports(String.class));
    }

    @Test
    public void expectedDomainObjectArgumentIsReturnedFromMethodInvocation() throws Exception {
        voter.setProcessDomainObjectClass(String.class);
        MethodInvocation mi = MethodInvocationUtils.create(new TestClass(), "methodTakingAString", "The Argument");
        assertEquals("The Argument", voter.getDomainObjectInstance(mi));
    }

    @Test
    public void expectedDomainObjectArgumentIsReturnedFromJoinPoint() throws Exception {
        voter.setProcessDomainObjectClass(String.class);
        Method method = TestClass.class.getMethod("methodTakingAString", new Class[] {String.class});
        MockJoinPoint joinPoint = new MockJoinPoint(new TestClass(), method, "The Argument");
        assertEquals("The Argument", voter.getDomainObjectInstance(joinPoint));
    }

    @Test
    public void correctArgumentIsSelectedFromMultipleArgs() throws Exception {
        voter.setProcessDomainObjectClass(String.class);
        MethodInvocation mi = MethodInvocationUtils.create(new TestClass(),
                "methodTakingAListAndAString", new ArrayList<Object>(), "The Argument");
        assertEquals("The Argument", voter.getDomainObjectInstance(mi));
    }

    private static class TestClass {
        public void methodTakingAString(String arg) {
        }

        public void methodTaking2Strings(String arg1, String arg2) {
        }

        public void methodTakingAListAndAString(ArrayList<Object> arg1, String arg2) {
        }
    }

}
