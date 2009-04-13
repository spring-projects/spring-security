package org.springframework.security.core.token;

import java.util.Date;

import junit.framework.Assert;

import org.junit.Test;
import org.springframework.security.core.token.DefaultToken;

/**
 * Tests {@link DefaultToken}.
 * 
 * @author Ben Alex
 *
 */
public class DefaultTokenTests {
    @Test
    public void testEquality() {
        String key = "key";
        long created = new Date().getTime();
        String extendedInformation = "extended";
        
        DefaultToken t1 = new DefaultToken(key, created, extendedInformation);
        DefaultToken t2 = new DefaultToken(key, created, extendedInformation);
        Assert.assertEquals(t1, t2);
    }
    
    @Test(expected=IllegalArgumentException.class)
    public void testRejectsNullExtendedInformation() {
        String key = "key";
        long created = new Date().getTime();
        new DefaultToken(key, created, null);
    }

    @Test
    public void testEqualityWithDifferentExtendedInformation3() {
        String key = "key";
        long created = new Date().getTime();
        
        DefaultToken t1 = new DefaultToken(key, created, "length1");
        DefaultToken t2 = new DefaultToken(key, created, "longerLength2");
        Assert.assertFalse(t1.equals(t2));
    }
}
