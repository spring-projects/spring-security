package org.springframework.security.acls.objectidentity;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.springframework.security.acls.IdentityUnavailableException;

/**
 * Tests for {@link ObjectIdentityImpl}.
 * 
 * @author Andrei Stefan
 */
public class ObjectIdentityTests extends TestCase {
	
	//~ Methods ========================================================================================================

	public void testConstructorsRequiredFields() {
		// Check one-argument constructor required field
		try {
			ObjectIdentity obj = new ObjectIdentityImpl(null);
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}

		// Check String-Serializable constructor required field
		try {
			ObjectIdentity obj = new ObjectIdentityImpl("", new Long(1));
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}

		// Check Serializable parameter is not null
		try {
			ObjectIdentity obj = new ObjectIdentityImpl(
					"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject", null);
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}

		// The correct way of using String-Serializable constructor
		try {
			ObjectIdentity obj = new ObjectIdentityImpl(
					"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject",
					new Long(1));
			Assert.assertTrue(true);
		}
		catch (IllegalArgumentException notExpected) {
			Assert.fail("It shouldn't have thrown IllegalArgumentException");
		}

		// Check the Class-Serializable constructor
		try {
			ObjectIdentity obj = new ObjectIdentityImpl(MockIdDomainObject.class, null);
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}
	}

	public void testGetIdMethodConstraints() {
		// Check the getId() method is present
		try {
			ObjectIdentity obj = new ObjectIdentityImpl("A_STRING_OBJECT");
			Assert.fail("It should have thrown IdentityUnavailableException");
		}
		catch (IdentityUnavailableException expected) {
			Assert.assertTrue(true);
		}

		// getId() should return a non-null value
		MockIdDomainObject mockId = new MockIdDomainObject();
		try {
			ObjectIdentity obj = new ObjectIdentityImpl(mockId);
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}

		// getId() should return a Serializable object
		mockId.setId(new MockIdDomainObject());
		try {
			ObjectIdentity obj = new ObjectIdentityImpl(mockId);
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}

		// getId() should return a Serializable object
		mockId.setId(new Long(100));
		try {
			ObjectIdentity obj = new ObjectIdentityImpl(mockId);
			Assert.assertTrue(true);
		}
		catch (IllegalArgumentException expected) {
			Assert.fail("It shouldn't have thrown IllegalArgumentException");
		}
	}

	public void testConstructorInvalidClassParameter() {
		try {
			ObjectIdentity obj = new ObjectIdentityImpl("not.a.Class", new Long(1));
		}
		catch (IllegalStateException expected) {
			return;
		}
		Assert.fail("It should have thrown IllegalStateException");
	}

	public void testEquals() {
		ObjectIdentity obj = new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject", new Long(1));
		MockIdDomainObject mockObj = new MockIdDomainObject();
		mockObj.setId(new Long(1));

		String string = "SOME_STRING";
		Assert.assertNotSame(obj, string);
		Assert.assertTrue(!obj.equals(null));
		Assert.assertTrue(!obj.equals("DIFFERENT_OBJECT_TYPE"));
		Assert.assertTrue(!obj
				.equals(new ObjectIdentityImpl(
						"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject",
						new Long(2))));
		Assert.assertTrue(!obj.equals(new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockOtherIdDomainObject",
				new Long(1))));
		Assert.assertEquals(
				new ObjectIdentityImpl(
						"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject",
						new Long(1)), obj);
		Assert.assertTrue(new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject", new Long(1))
				.equals(obj));
		Assert.assertTrue(new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject", new Long(1))
				.equals(new ObjectIdentityImpl(mockObj)));
	}

	public void testHashCode() {
		ObjectIdentity obj = new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject", new Long(1));
		Assert.assertEquals(new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject", new Long(1))
				.hashCode(), obj.hashCode());
		Assert.assertTrue(new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockOtherIdDomainObject",
				new Long(1)).hashCode() != obj.hashCode());
		Assert.assertTrue(new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject", new Long(2))
				.hashCode() != obj.hashCode());
	}
	
	public void testGetters() {
		ObjectIdentity obj = new ObjectIdentityImpl(
				"org.springframework.security.acls.objectidentity.ObjectIdentityTests$MockIdDomainObject", new Long(1));
		Assert.assertEquals(new Long(1), obj.getIdentifier());
		Assert.assertEquals(MockIdDomainObject.class, obj.getJavaType());
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
