/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import java.io.Serializable;
import java.lang.reflect.Method;

import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

/**
 * Simple implementation of {@link ObjectIdentity}.
 * <p>
 * Uses <code>String</code>s to store the identity of the domain object instance. Also
 * offers a constructor that uses reflection to build the identity information.
 *
 * @author Ben Alex
 */
public class ObjectIdentityImpl implements ObjectIdentity {
	// ~ Instance fields
	// ================================================================================================

	private final String type;
	private Serializable identifier;

	// ~ Constructors
	// ===================================================================================================

	public ObjectIdentityImpl(String type, Serializable identifier) {
		Assert.hasText(type, "Type required");
		Assert.notNull(identifier, "identifier required");

		this.identifier = identifier;
		this.type = type;
	}

	/**
	 * Constructor which uses the name of the supplied class as the <tt>type</tt>
	 * property.
	 */
	public ObjectIdentityImpl(Class<?> javaType, Serializable identifier) {
		Assert.notNull(javaType, "Java Type required");
		Assert.notNull(identifier, "identifier required");
		this.type = javaType.getName();
		this.identifier = identifier;
	}

	/**
	 * Creates the <code>ObjectIdentityImpl</code> based on the passed object instance.
	 * The passed object must provide a <code>getId()</code> method, otherwise an
	 * exception will be thrown.
	 * <p>
	 * The class name of the object passed will be considered the {@link #type}, so if
	 * more control is required, a different constructor should be used.
	 *
	 * @param object the domain object instance to create an identity for.
	 *
	 * @throws IdentityUnavailableException if identity could not be extracted
	 */
	public ObjectIdentityImpl(Object object) throws IdentityUnavailableException {
		Assert.notNull(object, "object cannot be null");

		Class<?> typeClass = ClassUtils.getUserClass(object.getClass());
		type = typeClass.getName();

		Object result;

		try {
			Method method = typeClass.getMethod("getId", new Class[] {});
			result = method.invoke(object);
		}
		catch (Exception e) {
			throw new IdentityUnavailableException(
					"Could not extract identity from object " + object, e);
		}

		Assert.notNull(result, "getId() is required to return a non-null value");
		Assert.isInstanceOf(Serializable.class, result,
				"Getter must provide a return value of type Serializable");
		this.identifier = (Serializable) result;
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * Important so caching operates properly.
	 * <p>
	 * Considers an object of the same class equal if it has the same
	 * <code>classname</code> and <code>id</code> properties.
	 * <p>
	 * Numeric identities (Integer and Long values) are considered equal if they are
	 * numerically equal. Other serializable types are evaluated using a simple equality.
	 *
	 * @param arg0 object to compare
	 *
	 * @return <code>true</code> if the presented object matches this object
	 */
	@Override
	public boolean equals(Object arg0) {
		if (arg0 == null || !(arg0 instanceof ObjectIdentityImpl)) {
			return false;
		}

		ObjectIdentityImpl other = (ObjectIdentityImpl) arg0;

		if (identifier instanceof Number && other.identifier instanceof Number) {
			// Integers and Longs with same value should be considered equal
			if (((Number) identifier).longValue() != ((Number) other.identifier)
					.longValue()) {
				return false;
			}
		}
		else {
			// Use plain equality for other serializable types
			if (!identifier.equals(other.identifier)) {
				return false;
			}
		}

		return type.equals(other.type);
	}

	@Override
	public Serializable getIdentifier() {
		return identifier;
	}

	@Override
	public String getType() {
		return type;
	}

	/**
	 * Important so caching operates properly.
	 *
	 * @return the hash
	 */
	@Override
	public int hashCode() {
		int result = this.type.hashCode();
		result = 31 * result + this.identifier.hashCode();
		return result;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(this.getClass().getName()).append("[");
		sb.append("Type: ").append(this.type);
		sb.append("; Identifier: ").append(this.identifier).append("]");

		return sb.toString();
	}
}
