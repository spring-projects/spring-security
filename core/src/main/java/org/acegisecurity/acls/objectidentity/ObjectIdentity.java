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

import java.io.Serializable;


/**
 * Interface representing the identity of an individual domain object instance.
 *
 * <P>
 * As implementations are used as the key for caching and lookup, it is
 * essential that implementations provide methods so that object-equality
 * rather than reference-equality can be relied upon by caches. In other
 * words, a cache can consider two <code>ObjectIdentity</code>s equal if
 * <code>identity1.equals(identity2)</code>, rather than reference-equality of
 * <code>identity1==identity2</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ObjectIdentity extends Serializable {
    //~ Methods ========================================================================================================

    /**
     * Refer to the <code>java.lang.Object</code> documentation for the interface contract.
     *
     * @param obj to be compared
     *
     * @return <code>true</code> if the objects are equal, <code>false</code> otherwise
     */
    boolean equals(Object obj);

    /**
     * Obtains the actual identifier. This identifier must not be reused to represent other domain objects with
     * the same <code>javaType</code>.<p>Because ACLs are largely immutable, it is strongly recommended to use
     * a synthetic identifier (such as a database sequence number for the primary key). Do not use an identifier with
     * business meaning, as that business meaning may change.</p>
     *
     * @return the identifier (unique within this <code>javaType</code>
     */
    Serializable getIdentifier();

    /**
     * Obtains the Java type represented by the domain object.
     *
     * @return the Java type of the domain object
     */
    Class getJavaType();

    /**
     * Refer to the <code>java.lang.Object</code> documentation for the interface contract.
     *
     * @return a hash code representation of this object
     */
    int hashCode();
}
