/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.acegisecurity.acls.objectidentity;

import org.acegisecurity.acls.IdentityUnavailableException;

import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

import java.io.Serializable;

import java.lang.reflect.Method;


/**
 * Simple implementation of {@link org.acegisecurity.acl.basic.AclObjectIdentity AclObjectIdentity}.
 * <p>
 * Uses <code>String</code>s to store the identity of the domain object instance. Also offers a constructor that uses
 * reflection to build the identity information.
 * </p>
 */
public class ObjectIdentityImpl implements ObjectIdentity {
    //~ Instance fields ================================================================================================

    private Class javaType;
    private Serializable identifier;

    //~ Constructors ===================================================================================================

    public ObjectIdentityImpl(String javaType, Serializable identifier) {
        Assert.hasText(javaType, "Java Type required");
        Assert.notNull(identifier, "identifier required");

        try {
            this.javaType = Class.forName(javaType);
        } catch (Exception ex) {
            ReflectionUtils.handleReflectionException(ex);
        }

        this.identifier = identifier;
    }

    public ObjectIdentityImpl(Class javaType, Serializable identifier) {
        Assert.notNull(javaType, "Java Type required");
        Assert.notNull(identifier, "identifier required");
        this.javaType = javaType;
        this.identifier = identifier;
    }

/**
     * Creates the <code>ObjectIdentityImpl</code> based on the passed
     * object instance. The passed object must provide a <code>getId()</code>
     * method, otherwise an exception will be thrown. The object passed will
     * be considered the {@link #javaType}, so if more control is required,
     * an alternate constructor should be used instead.
     *
     * @param object the domain object instance to create an identity for
     *
     * @throws IdentityUnavailableException if identity could not be extracted
     */
    public ObjectIdentityImpl(Object object) throws IdentityUnavailableException {
        Assert.notNull(object, "object cannot be null");

        this.javaType = object.getClass();

        Object result;

        try {
            Method method = this.javaType.getMethod("getId", new Class[] {});
            result = method.invoke(object, new Object[] {});
        } catch (Exception e) {
            throw new IdentityUnavailableException("Could not extract identity from object " + object, e);
        }

        Assert.notNull(result, "getId() is required to return a non-null value");
        Assert.isInstanceOf(Serializable.class, result, "Getter must provide a return value of type Serializable");
        this.identifier = (Serializable) result;
    }

    //~ Methods ========================================================================================================

    /**
     * Important so caching operates properly.<P>Considers an object of the same class equal if it has the same
     * <code>classname</code> and <code>id</code> properties.</p>
     *
     * @param arg0 object to compare
     *
     * @return <code>true</code> if the presented object matches this object
     */
    public boolean equals(Object arg0) {
        if (arg0 == null) {
            return false;
        }

        if (!(arg0 instanceof ObjectIdentityImpl)) {
            return false;
        }

        ObjectIdentityImpl other = (ObjectIdentityImpl) arg0;

        if (this.getIdentifier().equals(other.getIdentifier()) && this.getJavaType().equals(other.getJavaType())) {
            return true;
        }

        return false;
    }

    public Serializable getIdentifier() {
        return identifier;
    }

    public Class getJavaType() {
        return javaType;
    }

    /**
     * Important so caching operates properly.
     *
     * @return the hash
     */
    public int hashCode() {
        int code = 31;
        code ^= this.javaType.hashCode();
        code ^= this.identifier.hashCode();

        return code;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(this.getClass().getName()).append("[");
        sb.append("Java Type: ").append(this.javaType);
        sb.append("; Identifier: ").append(this.identifier).append("]");

        return sb.toString();
    }
}
