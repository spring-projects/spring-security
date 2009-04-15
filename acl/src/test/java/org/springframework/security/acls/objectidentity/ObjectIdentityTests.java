package org.springframework.security.acls.objectidentity;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Tests for {@link ObjectIdentityImpl}.
 *
 * @author Andrei Stefan
 */
public class ObjectIdentityTests {

    private static final String DOMAIN_CLASS =
        "org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject";

    //~ Methods ========================================================================================================

    @Test
    public void constructorsRespectRequiredFields() throws Exception {
        // Check one-argument constructor required field
        try {
            new ObjectIdentityImpl(null);
            fail("It should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        // Check String-Serializable constructor required field
        try {
            new ObjectIdentityImpl("", new Long(1));
            fail("It should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        // Check Serializable parameter is not null
        try {
            new ObjectIdentityImpl(DOMAIN_CLASS, null);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }

        // The correct way of using String-Serializable constructor
        try {
            new ObjectIdentityImpl(DOMAIN_CLASS, new Long(1));
        }
        catch (IllegalArgumentException notExpected) {
            fail("It shouldn't have thrown IllegalArgumentException");
        }

        // Check the Class-Serializable constructor
        try {
            new ObjectIdentityImpl(MockIdDomainObject.class, null);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {

        }
    }

    @Test
    public void testGetIdMethodConstraints() throws Exception {
        // Check the getId() method is present
        try {
            new ObjectIdentityImpl("A_STRING_OBJECT");
            fail("It should have thrown IdentityUnavailableException");
        }
        catch (IdentityUnavailableException expected) {

        }

        // getId() should return a non-null value
        MockIdDomainObject mockId = new MockIdDomainObject();
        try {
            new ObjectIdentityImpl(mockId);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {

        }

        // getId() should return a Serializable object
        mockId.setId(new MockIdDomainObject());
        try {
            new ObjectIdentityImpl(mockId);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }

        // getId() should return a Serializable object
        mockId.setId(new Long(100));
        try {
            new ObjectIdentityImpl(mockId);
        }
        catch (IllegalArgumentException expected) {
        }
    }

    @Test(expected=IllegalStateException.class)
    public void testConstructorInvalidClassParameter() throws Exception {
        new ObjectIdentityImpl("not.a.Class", new Long(1));
    }

    @Test
    public void testEquals() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, new Long(1));
        MockIdDomainObject mockObj = new MockIdDomainObject();
        mockObj.setId(new Long(1));

        String string = "SOME_STRING";
        assertNotSame(obj, string);
        assertFalse(obj.equals(null));
        assertFalse(obj.equals("DIFFERENT_OBJECT_TYPE"));
        assertFalse(obj.equals(new ObjectIdentityImpl(DOMAIN_CLASS,new Long(2))));
        assertFalse(obj.equals(new ObjectIdentityImpl(
                "org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockOtherIdDomainObject",
                new Long(1))));
        assertEquals(new ObjectIdentityImpl(DOMAIN_CLASS,new Long(1)), obj);
        assertEquals(obj, new ObjectIdentityImpl(mockObj));
    }

    @Test
    public void testHashCode() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, new Long(1));
        assertEquals(new ObjectIdentityImpl(DOMAIN_CLASS, new Long(1)).hashCode(), obj.hashCode());
        assertTrue(new ObjectIdentityImpl(
                "org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockOtherIdDomainObject",
                new Long(1)).hashCode() != obj.hashCode());
        assertTrue(new ObjectIdentityImpl(DOMAIN_CLASS, new Long(2)).hashCode() != obj.hashCode());
    }

/*    public void testHashCodeDifferentSerializableTypes() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(
                DOMAIN_CLASS, new Long(1));
        assertEquals(new ObjectIdentityImpl(
                DOMAIN_CLASS, "1")
                .hashCode(), obj.hashCode());
        assertEquals(new ObjectIdentityImpl(
                DOMAIN_CLASS,
                new Integer(1)).hashCode(), obj.hashCode());
    }*/

    @Test
    public void testGetters() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, new Long(1));
        assertEquals(new Long(1), obj.getIdentifier());
        assertEquals(MockIdDomainObject.class, obj.getJavaType());
    }

    //~ Inner Classes ==================================================================================================

    private class MockIdDomainObject {
        private Object id;

        public Object getId() {
            return id;
        }

        public void setId(Object id) {
            this.id = id;
        }
    }

    @SuppressWarnings("unused")
    private class MockOtherIdDomainObject {
        private Object id;

        public Object getId() {
            return id;
        }

        public void setId(Object id) {
            this.id = id;
        }
    }
}
