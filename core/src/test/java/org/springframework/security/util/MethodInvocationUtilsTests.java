package org.springframework.security.util;

import static org.junit.Assert.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;

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
    public void createFromClassWithNoArgInfoReturnsNullForMethodWithArgs() {
        MethodInvocation mi = MethodInvocationUtils.createFromClass(String.class, "codePointAt");
        assertNull(mi);
    }

    @Test
    public void createFromClassReturnsMethodIfGivArgInfoForMethodWithArgs() {
        MethodInvocation mi = MethodInvocationUtils.createFromClass(null, String.class, "compareTo",
                new Class<?>[]{String.class}, new Object[] {""});
        assertNotNull(mi);
    }

}
