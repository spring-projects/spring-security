package org.springframework.security.util;

import static org.junit.Assert.*;

import org.junit.*;

/**
 * @author Luke Taylor
 */
public class InMemoryResourceTests {

    @Test
    public void resourceContainsExpectedData() throws Exception {
        InMemoryResource resource = new InMemoryResource("blah");
        assertNull(resource.getDescription());
        assertEquals(1, resource.hashCode());
        assertNotNull(resource.getInputStream());
    }

    @Test
    public void resourceIsEqualToOneWithSameContent() throws Exception {
        assertEquals(new InMemoryResource("xxx"), new InMemoryResource("xxx"));
        assertFalse(new InMemoryResource("xxx").equals(new InMemoryResource("xxxx")));
        assertFalse(new InMemoryResource("xxx").equals(new Object()));
    }
}
