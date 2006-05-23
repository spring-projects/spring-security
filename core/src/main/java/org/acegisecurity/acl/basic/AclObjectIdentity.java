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

package org.acegisecurity.acl.basic;

import java.io.Serializable;


/**
 * Interface representing the identity of an individual domain object instance.
 * 
 * <P>
 * It should be noted that <code>AclObjectIdentity</code> instances are created
 * in various locations throughout the package. As
 * <code>AclObjectIdentity</code>s are used as the key for caching, it is
 * essential that implementations provide methods so that object-equality
 * rather than reference-equality can be relied upon by caches. In other
 * words, a cache can consider two <code>AclObjectIdentity</code>s equal if
 * <code>identity1.equals(identity2)</code>, rather than reference-equality of
 * <code>identity1==identity2</code>.
 * </p>
 * 
 * <P>
 * In practical terms this means you must implement the standard
 * <code>java.lang.Object</code> methods shown below. Depending on your
 * cache's internal structure, you may also need to implement special
 * interfaces such as <code>java.util.Comparator</code> or
 * <code>java.lang.Comparable</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AclObjectIdentity extends Serializable {
    //~ Methods ========================================================================================================

    /**
     * Refer to the <code>java.lang.Object</code> documentation for the interface contract.
     *
     * @param obj to be compared
     *
     * @return <code>true</code> if the objects are equal, <code>false</code> otherwise
     */
    public boolean equals(Object obj);

    /**
     * Refer to the <code>java.lang.Object</code> documentation for the interface contract.
     *
     * @return a hash code representation of this object
     */
    public int hashCode();
}
