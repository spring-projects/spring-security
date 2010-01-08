package org.springframework.security.acls.domain;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.acls.domain.IdentityUnavailableException;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.ObjectIdentity;

/**
 * Tests for {@link ObjectIdentityImpl}.
 *
 * @author Andrei Stefan
 */
@SuppressWarnings("unused")
public class ObjectIdentityImplTests {

    private static final String DOMAIN_CLASS =
        "org.springframework.security.acls.domain.ObjectIdentityImplTests$MockIdDomainObject";

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
            new ObjectIdentityImpl("", Long.valueOf(1));
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
            new ObjectIdentityImpl(DOMAIN_CLASS, Long.valueOf(1));
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
    public void gettersReturnExpectedValues() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, Long.valueOf(1));
        assertEquals(Long.valueOf(1), obj.getIdentifier());
        assertEquals(MockIdDomainObject.class.getName(), obj.getType());
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

    @Test(expected=IllegalArgumentException.class)
    public void constructorRejectsInvalidTypeParameter() throws Exception {
        new ObjectIdentityImpl("", Long.valueOf(1));
    }

    @Test
    public void testEquals() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, Long.valueOf(1));
        MockIdDomainObject mockObj = new MockIdDomainObject();
        mockObj.setId(Long.valueOf(1));

        String string = "SOME_STRING";
        assertNotSame(obj, string);
        assertFalse(obj.equals(null));
        assertFalse(obj.equals("DIFFERENT_OBJECT_TYPE"));
        assertFalse(obj.equals(new ObjectIdentityImpl(DOMAIN_CLASS, Long.valueOf(2))));
        assertFalse(obj.equals(new ObjectIdentityImpl(
                "org.springframework.security.acls.domain.ObjectIdentityImplTests$MockOtherIdDomainObject",
                Long.valueOf(1))));
        assertEquals(new ObjectIdentityImpl(DOMAIN_CLASS,Long.valueOf(1)), obj);
        assertEquals(obj, new ObjectIdentityImpl(mockObj));
    }

    @Test
    public void hashcodeIsDifferentForDifferentJavaTypes() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(Object.class, Long.valueOf(1));
        ObjectIdentity obj2 = new ObjectIdentityImpl(String.class, Long.valueOf(1));
        assertFalse(obj.hashCode() == obj2.hashCode());
    }

    @Test
    public void longAndIntegerIdsWithSameValueAreEqualAndHaveSameHashcode() {
        ObjectIdentity obj = new ObjectIdentityImpl(Object.class, new Long(5));
        ObjectIdentity obj2 = new ObjectIdentityImpl(Object.class, new Integer(5));

        assertEquals(obj, obj2);
        assertEquals(obj.hashCode(), obj2.hashCode());
    }

    @Test
    public void equalStringIdsAreEqualAndHaveSameHashcode() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(Object.class, "1000");
        ObjectIdentity obj2 = new ObjectIdentityImpl(Object.class, "1000");
        assertEquals(obj, obj2);
        assertEquals(obj.hashCode(), obj2.hashCode());
    }

    @Test
    public void stringAndNumericIdsAreNotEqual() throws Exception {
        ObjectIdentity obj = new ObjectIdentityImpl(Object.class, "1000");
        ObjectIdentity obj2 = new ObjectIdentityImpl(Object.class, Long.valueOf(1000));
        assertFalse(obj.equals(obj2));
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
