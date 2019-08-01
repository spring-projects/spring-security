/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls.domain;

import static org.assertj.core.api.Assertions.*;

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

	private static final String DOMAIN_CLASS = "org.springframework.security.acls.domain.ObjectIdentityImplTests$MockIdDomainObject";

	// ~ Methods
	// ========================================================================================================

	@Test
	public void constructorsRespectRequiredFields() throws Exception {
		// Check one-argument constructor required field
		try {
			new ObjectIdentityImpl(null);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		// Check String-Serializable constructor required field
		try {
			new ObjectIdentityImpl("", 1L);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
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
			new ObjectIdentityImpl(DOMAIN_CLASS, 1L);
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
		ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, 1L);
		assertThat(obj.getIdentifier()).isEqualTo(1L);
		assertThat(obj.getType()).isEqualTo(MockIdDomainObject.class.getName());
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
		mockId.setId(100L);
		try {
			new ObjectIdentityImpl(mockId);
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorRejectsInvalidTypeParameter() throws Exception {
		new ObjectIdentityImpl("", 1L);
	}

	@Test
	public void testEquals() throws Exception {
		ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, 1L);
		MockIdDomainObject mockObj = new MockIdDomainObject();
		mockObj.setId(1L);

		String string = "SOME_STRING";
		assertThat(string).isNotSameAs(obj);
		assertThat(obj).isNotNull();
		assertThat(obj).isNotEqualTo("DIFFERENT_OBJECT_TYPE");
		assertThat(obj).isNotEqualTo(new ObjectIdentityImpl(DOMAIN_CLASS, 2L));
		assertThat(obj).isNotEqualTo(new ObjectIdentityImpl(
						"org.springframework.security.acls.domain.ObjectIdentityImplTests$MockOtherIdDomainObject",
				1L));
		assertThat(new ObjectIdentityImpl(DOMAIN_CLASS, 1L)).isEqualTo(obj);
		assertThat(new ObjectIdentityImpl(mockObj)).isEqualTo(obj);
	}

	@Test
	public void hashcodeIsDifferentForDifferentJavaTypes() throws Exception {
		ObjectIdentity obj = new ObjectIdentityImpl(Object.class, 1L);
		ObjectIdentity obj2 = new ObjectIdentityImpl(String.class, 1L);
		assertThat(obj.hashCode()).isNotEqualTo(obj2.hashCode());
	}

	@Test
	public void longAndIntegerIdsWithSameValueAreEqualAndHaveSameHashcode() {
		ObjectIdentity obj = new ObjectIdentityImpl(Object.class, 5L);
		ObjectIdentity obj2 = new ObjectIdentityImpl(Object.class, 5);

		assertThat(obj2).isEqualTo(obj);
		assertThat(obj2.hashCode()).isEqualTo(obj.hashCode());
	}

	@Test
	public void equalStringIdsAreEqualAndHaveSameHashcode() throws Exception {
		ObjectIdentity obj = new ObjectIdentityImpl(Object.class, "1000");
		ObjectIdentity obj2 = new ObjectIdentityImpl(Object.class, "1000");
		assertThat(obj2).isEqualTo(obj);
		assertThat(obj2.hashCode()).isEqualTo(obj.hashCode());
	}

	@Test
	public void stringAndNumericIdsAreNotEqual() throws Exception {
		ObjectIdentity obj = new ObjectIdentityImpl(Object.class, "1000");
		ObjectIdentity obj2 = new ObjectIdentityImpl(Object.class, 1000L);
		assertThat(obj).isNotEqualTo(obj2);
	}

	// ~ Inner Classes
	// ==================================================================================================

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
