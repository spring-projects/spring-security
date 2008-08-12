package org.springframework.security.intercept.method;

import static org.junit.Assert.*;

import java.lang.reflect.Method;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.ConfigAttributeDefinition;

/**
 * Tests for {@link MapBasedMethodDefinitionSource}.
 *
 * @author Luke Taylor
 * @since 2.0.4
 */
public class MapBasedMethodDefinitionSourceTests {
    private final ConfigAttributeDefinition ROLE_A = new ConfigAttributeDefinition("ROLE_A");
    private final ConfigAttributeDefinition ROLE_B = new ConfigAttributeDefinition("ROLE_B");
    private MapBasedMethodDefinitionSource mds;
    private Method someMethodString;
    private Method someMethodInteger;

    @Before
    public void initialize() throws Exception {
        mds = new MapBasedMethodDefinitionSource();
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
