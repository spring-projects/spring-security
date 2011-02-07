package org.springframework.security.util;

import static org.junit.Assert.*;

import org.junit.*;

/**
 * @author Luke Taylor
 */
public class FieldUtilsTests {

    @Test
    public void gettingAndSettingProtectedFieldIsSuccessful() throws Exception {
        new FieldUtils();

        Object tc = new TestClass();

        assertEquals("x", FieldUtils.getProtectedFieldValue("protectedField", tc));
        assertEquals("z", FieldUtils.getFieldValue(tc, "nested.protectedField"));
        FieldUtils.setProtectedFieldValue("protectedField", tc, "y");
        assertEquals("y", FieldUtils.getProtectedFieldValue("protectedField", tc));

        try {
            FieldUtils.getProtectedFieldValue("nonExistentField", tc);
        } catch (IllegalStateException expected) {
        }
    }
}

@SuppressWarnings("unused")
class TestClass {
    private String protectedField = "x";
    private Nested nested = new Nested();
}

@SuppressWarnings("unused")
class Nested {
    private String protectedField = "z";
}
