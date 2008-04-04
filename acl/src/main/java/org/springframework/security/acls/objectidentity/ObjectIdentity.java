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
package org.springframework.security.acls.objectidentity;

import java.io.Serializable;


/**
 * Represents the identity of an individual domain object instance.
 *
 * <p>
 * As implementations of <tt>ObjectIdentity</tt> are used as the key to represent 
 * domain objects in the ACL subsystem, it is essential that implementations provide
 * methods so that object-equality rather than reference-equality can be relied upon
 * reliably. In other words, the ACL subsystem can consider two 
 * <tt>ObjectIdentity</tt>s equal if <tt>identity1.equals(identity2)</tt>, rather than 
 * reference-equality of <tt>identity1==identity2</tt>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ObjectIdentity extends Serializable {
    //~ Methods ========================================================================================================

    /**
     * @param obj to be compared
     *
     * @return <tt>true</tt> if the objects are equal, <tt>false</tt> otherwise
     * @see Object#equals(Object)
     */
    boolean equals(Object obj);

    /**
     * Obtains the actual identifier. This identifier must not be reused to represent other domain objects with
     * the same <tt>javaType</tt>.
     * 
     * <p>Because ACLs are largely immutable, it is strongly recommended to use
     * a synthetic identifier (such as a database sequence number for the primary key). Do not use an identifier with
     * business meaning, as that business meaning may change in the future such change will cascade to the ACL 
     * subsystem data.</p>
     *
     * @return the identifier (unique within this <tt>javaType</tt>; never <tt>null</tt>)
     */
    Serializable getIdentifier();

    /**
     * Obtains the Java type represented by the domain object. The Java type can be an interface or a class, but is
     * most often the domain object implementation class.
     *
     * @return the Java type of the domain object (never <tt>null</tt>)
     */
    Class getJavaType();

    /**
     * @return a hash code representation of the <tt>ObjectIdentity</tt>
     * @see Object#hashCode()
     */
    int hashCode();
}
