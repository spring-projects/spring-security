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

import org.junit.Test;

import org.springframework.security.acls.model.ObjectIdentity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link ObjectIdentityImpl}.
 *
 * @author Andrei Stefan
 */
@SuppressWarnings("unused")
public class ObjectIdentityImplTests {

	private static final String DOMAIN_CLASS = "org.springframework.security.acls.domain.ObjectIdentityImplTests$MockIdDomainObject";

	@Test
	public void constructorsRespectRequiredFields() {
		// Check one-argument constructor required field
		assertThatIllegalArgumentException().isThrownBy(() -> new ObjectIdentityImpl(null));
		// Check String-Serializable constructor required field
		assertThatIllegalArgumentException().isThrownBy(() -> new ObjectIdentityImpl("", 1L));
		// Check Serializable parameter is not null
		assertThatIllegalArgumentException().isThrownBy(() -> new ObjectIdentityImpl(DOMAIN_CLASS, null));
		// The correct way of using String-Serializable constructor
		assertThatNoException().isThrownBy(() -> new ObjectIdentityImpl(DOMAIN_CLASS, 1L));
		// Check the Class-Serializable constructor
		assertThatIllegalArgumentException().isThrownBy(() -> new ObjectIdentityImpl(MockIdDomainObject.class, null));
	}

	@Test
	public void gettersReturnExpectedValues() {
		ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, 1L);
		assertThat(obj.getIdentifier()).isEqualTo(1L);
		assertThat(obj.getType()).isEqualTo(MockIdDomainObject.class.getName());
	}

	@Test
	public void testGetIdMethodConstraints() {
		// Check the getId() method is present
		assertThatExceptionOfType(IdentityUnavailableException.class)
				.isThrownBy(() -> new ObjectIdentityImpl("A_STRING_OBJECT"));
		// getId() should return a non-null value
		MockIdDomainObject mockId = new MockIdDomainObject();
		assertThatIllegalArgumentException().isThrownBy(() -> new ObjectIdentityImpl(mockId));
		// getId() should return a Serializable object
		mockId.setId(new MockIdDomainObject());
		assertThatIllegalArgumentException().isThrownBy(() -> new ObjectIdentityImpl(mockId));
		// getId() should return a Serializable object
		mockId.setId(100L);
		assertThatNoException().isThrownBy(() -> new ObjectIdentityImpl(mockId));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorRejectsInvalidTypeParameter() {
		new ObjectIdentityImpl("", 1L);
	}

	@Test
	public void testEquals() {
		ObjectIdentity obj = new ObjectIdentityImpl(DOMAIN_CLASS, 1L);
		MockIdDomainObject mockObj = new MockIdDomainObject();
		mockObj.setId(1L);
		String string = "SOME_STRING";
		assertThat(string).isNotSameAs(obj);
		assertThat(obj).isNotNull();
		assertThat(obj).isNotEqualTo("DIFFERENT_OBJECT_TYPE");
		assertThat(obj).isNotEqualTo(new ObjectIdentityImpl(DOMAIN_CLASS, 2L));
		assertThat(obj).isNotEqualTo(new ObjectIdentityImpl(
				"org.springframework.security.acls.domain.ObjectIdentityImplTests$MockOtherIdDomainObject", 1L));
		assertThat(new ObjectIdentityImpl(DOMAIN_CLASS, 1L)).isEqualTo(obj);
		assertThat(new ObjectIdentityImpl(mockObj)).isEqualTo(obj);
	}

	@Test
	public void hashcodeIsDifferentForDifferentJavaTypes() {
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
	public void equalStringIdsAreEqualAndHaveSameHashcode() {
		ObjectIdentity obj = new ObjectIdentityImpl(Object.class, "1000");
		ObjectIdentity obj2 = new ObjectIdentityImpl(Object.class, "1000");
		assertThat(obj2).isEqualTo(obj);
		assertThat(obj2.hashCode()).isEqualTo(obj.hashCode());
	}

	@Test
	public void stringAndNumericIdsAreNotEqual() {
		ObjectIdentity obj = new ObjectIdentityImpl(Object.class, "1000");
		ObjectIdentity obj2 = new ObjectIdentityImpl(Object.class, 1000L);
		assertThat(obj).isNotEqualTo(obj2);
	}

	private class MockIdDomainObject {

		private Object id;

		public Object getId() {
			return this.id;
		}

		public void setId(Object id) {
			this.id = id;
		}

	}

	private class MockOtherIdDomainObject {

		private Object id;

		public Object getId() {
			return this.id;
		}

		public void setId(Object id) {
			this.id = id;
		}

	}

}
