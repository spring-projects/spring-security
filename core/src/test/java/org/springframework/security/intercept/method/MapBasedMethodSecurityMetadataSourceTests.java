package org.springframework.security.intercept.method;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Method;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.SecurityConfig;

/**
 * Tests for {@link MapBasedMethodSecurityMetadataSource}.
 *
 * @author Luke Taylor
 * @since 2.0.4
 */
public class MapBasedMethodSecurityMetadataSourceTests {
    private final List<ConfigAttribute> ROLE_A = SecurityConfig.createList("ROLE_A");
    private final List<ConfigAttribute> ROLE_B = SecurityConfig.createList("ROLE_B");
    private MapBasedMethodSecurityMetadataSource mds;
    private Method someMethodString;
    private Method someMethodInteger;

    @Before
    public void initialize() throws Exception {
        mds = new MapBasedMethodSecurityMetadataSource();
        someMethodString = MockService.class.getMethod("someMethod", String.class);
        someMethodInteger = MockService.class.getMethod("someMethod", Integer.class);
    }

    @Test
    public void wildcardedMatchIsOverwrittenByMoreSpecificMatch() {
        mds.addSecureMethod(MockService.class, "some*", ROLE_A);
        mds.addSecureMethod(MockService.class, "someMethod*", ROLE_B);
        assertEquals(ROLE_B, mds.getAttributes(someMethodInteger, MockService.class));
    }

    @Test
    public void methodsWithDifferentArgumentsAreMatchedCorrectly() throws Exception {
        mds.addSecureMethod(MockService.class, someMethodInteger, ROLE_A);
        mds.addSecureMethod(MockService.class, someMethodString, ROLE_B);

        assertEquals(ROLE_A, mds.getAttributes(someMethodInteger, MockService.class));
        assertEquals(ROLE_B, mds.getAttributes(someMethodString, MockService.class));
    }

    private class MockService {
        public void someMethod(String s) {
        }

        public void someMethod(Integer i) {
        }
    }
}
