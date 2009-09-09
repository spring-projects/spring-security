package org.springframework.security.util;

import static org.junit.Assert.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.springframework.security.access.annotation.BusinessServiceImpl;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class MethodInvocationUtilsTests {

    @Test
    public void createFromClassReturnsMethodWithNoArgInfoForMethodWithNoArgs() {
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

}
