package org.springframework.security.util;

import static org.junit.Assert.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.*;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.security.access.annotation.BusinessServiceImpl;

import java.io.Serializable;

/**
 *
 * @author Luke Taylor
 */
public class MethodInvocationUtilsTests {

    @Test
    public void createFromClassReturnsMethodWithNoArgInfoForMethodWithNoArgs() {
        new MethodInvocationUtils();

        MethodInvocation mi = MethodInvocationUtils.createFromClass(String.class, "length");
        assertNotNull(mi);
    }

    @Test
    public void createFromClassReturnsMethodIfArgInfoOmittedAndMethodNameIsUnique() {
        MethodInvocation mi = MethodInvocationUtils.createFromClass(BusinessServiceImpl.class, "methodReturningAnArray");
        assertNotNull(mi);
    }

    @Test(expected=IllegalArgumentException.class)
    public void exceptionIsRaisedIfArgInfoOmittedAndMethodNameIsNotUnique() {
        MethodInvocationUtils.createFromClass(BusinessServiceImpl.class, "methodReturningAList");
    }

    @Test
    public void createFromClassReturnsMethodIfGivenArgInfoForMethodWithArgs() {
        MethodInvocation mi = MethodInvocationUtils.createFromClass(null, String.class, "compareTo",
                new Class<?>[]{String.class}, new Object[] {""});
        assertNotNull(mi);
    }

    @Test
    public void createFromObjectLocatesExistingMethods() throws Exception {
        AdvisedTarget t = new AdvisedTarget();
        // Just lie about interfaces
        t.setInterfaces(new Class[] {Serializable.class, MethodInvocation.class, Blah.class});

        MethodInvocation mi = MethodInvocationUtils.create(t, "blah");
        assertNotNull(mi);

        t.setProxyTargetClass(true);
        mi = MethodInvocationUtils.create(t, "blah");
        assertNotNull(mi);

        assertNull(MethodInvocationUtils.create(t, "blah", "non-existent arg"));
    }

    interface Blah {
        void blah();
    }

    class AdvisedTarget extends AdvisedSupport implements Blah {
        public void blah() {
        }
    }
}
