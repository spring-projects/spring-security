package org.springframework.security.web.access.intercept;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.web.access.intercept.RequestKey;

/**
 *
 * @author Luke Taylor
 *
 */
public class RequestKeyTests {

    @Test
    public void equalsWorksWithNullHttpMethod() {
        RequestKey key1 = new RequestKey("/someurl");
        RequestKey key2 = new RequestKey("/someurl");

        assertEquals(key1, key2);
        key1 = new RequestKey("/someurl","GET");
        assertFalse(key1.equals(key2));
        assertFalse(key2.equals(key1));
    }

    @Test
    public void keysWithSameUrlAndHttpMethodAreEqual() {
        RequestKey key1 = new RequestKey("/someurl", "GET");
        RequestKey key2 = new RequestKey("/someurl", "GET");

        assertEquals(key1, key2);
    }

    @Test
    public void keysWithSameUrlAndDifferentHttpMethodAreNotEqual() {
        RequestKey key1 = new RequestKey("/someurl", "GET");
        RequestKey key2 = new RequestKey("/someurl", "POST");

        assertFalse(key1.equals(key2));
        assertFalse(key2.equals(key1));
    }

    @Test
    public void keysWithDifferentUrlsAreNotEquals() {
        RequestKey key1 = new RequestKey("/someurl", "GET");
        RequestKey key2 = new RequestKey("/anotherurl", "GET");

        assertFalse(key1.equals(key2));
        assertFalse(key2.equals(key1));
    }
}
