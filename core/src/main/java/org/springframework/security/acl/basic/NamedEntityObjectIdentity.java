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

package org.springframework.security.acl.basic;

import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;


/**
 * Simple implementation of {@link AclObjectIdentity}.<P>Uses <code>String</code>s to store the identity of the
 * domain object instance. Also offers a constructor that uses reflection to build the identity information.</p>
 * @deprecated Use new spring-security-acl module instead
 */
public class NamedEntityObjectIdentity implements AclObjectIdentity {
    //~ Instance fields ================================================================================================

    private String classname;
    private String id;

    //~ Constructors ===================================================================================================

    public NamedEntityObjectIdentity(String classname, String id) {
        Assert.hasText(classname, "classname required");
        Assert.hasText(id, "id required");
        this.classname = classname;
        this.id = id;
    }

/**
     * Creates the <code>NamedEntityObjectIdentity</code> based on the passed
     * object instance. The passed object must provide a <code>getId()</code>
     * method, otherwise an exception will be thrown.
     *
     * @param object the domain object instance to create an identity for
     *
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     * @throws IllegalArgumentException
     */
    public NamedEntityObjectIdentity(Object object) throws IllegalAccessException, InvocationTargetException {
        Assert.notNull(object, "object cannot be null");

        this.classname = (getPackageName(object.getClass().getName()) == null)
            ? ClassUtils.getShortName(object.getClass())
            : (getPackageName(object.getClass().getName()) + "." + ClassUtils.getShortName(object.getClass()));

        Class clazz = object.getClass();

        try {
            Method method = clazz.getMethod("getId", new Class[] {});
            Object result = method.invoke(object, new Object[] {});
            this.id = result.toString();
        } catch (NoSuchMethodException nsme) {
            throw new IllegalArgumentException("Object of class '" + clazz
                + "' does not provide the required getId() method: " + object);
        }
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

        if (!(arg0 instanceof NamedEntityObjectIdentity)) {
            return false;
        }

        NamedEntityObjectIdentity other = (NamedEntityObjectIdentity) arg0;

        if (this.getId().equals(other.getId()) && this.getClassname().equals(other.getClassname())) {
            return true;
        }

        return false;
    }

    /**
     * Indicates the classname portion of the object identity.
     *
     * @return the classname (never <code>null</code>)
     */
    public String getClassname() {
        return classname;
    }

    /**
     * Indicates the instance identity portion of the object identity.
     *
     * @return the instance identity (never <code>null</code>)
     */
    public String getId() {
        return id;
    }

    private String getPackageName(String className) {
        Assert.hasLength(className, "class name must not be empty");

        int lastDotIndex = className.lastIndexOf(".");

        if (lastDotIndex == -1) {
            return null;
        }

        return className.substring(0, lastDotIndex);
    }

    /**
     * Important so caching operates properly.
     *
     * @return the hash of the classname and id
     */
    public int hashCode() {
        StringBuffer sb = new StringBuffer();
        sb.append(this.classname).append(this.id);

        return sb.toString().hashCode();
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(this.getClass().getName()).append("[");
        sb.append("Classname: ").append(this.classname);
        sb.append("; Identity: ").append(this.id).append("]");

        return sb.toString();
    }
}
