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
package org.springframework.security.acls;

import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.sid.Sid;

import java.util.Map;


/**
 * Provides retrieval of {@link Acl} instances.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AclService {
    //~ Methods ========================================================================================================

    /**
     * Locates all object identities that use the specified parent.  This is useful for administration tools.
     *
     * @param parentIdentity to locate children of
     *
     * @return the children (or <code>null</code> if none were found)
     */
    ObjectIdentity[] findChildren(ObjectIdentity parentIdentity);

    /**
     * Same as {@link #readAclsById(ObjectIdentity[])} except it returns only a single Acl.<p>This method
     * should not be called as it does not leverage the underlaying implementation's potential ability to filter
     * <code>Acl</code> entries based on a {@link Sid} parameter.</p>
     *
     * @param object DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws NotFoundException DOCUMENT ME!
     */
    Acl readAclById(ObjectIdentity object) throws NotFoundException;

    /**
     * Same as {@link #readAclsById(ObjectIdentity[], Sid[])} except it returns only a single Acl.
     *
     * @param object DOCUMENT ME!
     * @param sids DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws NotFoundException DOCUMENT ME!
     */
    Acl readAclById(ObjectIdentity object, Sid[] sids)
        throws NotFoundException;

    /**
     * Obtains all the <code>Acl</code>s that apply for the passed <code>Object</code>s.<p>The returned map is
     * keyed on the passed objects, with the values being the <code>Acl</code> instances. Any unknown objects will not
     * have a map key.</p>
     *
     * @param objects the objects to find ACL information for
     *
     * @return a map with zero or more elements (never <code>null</code>)
     *
     * @throws NotFoundException DOCUMENT ME!
     */
    Map readAclsById(ObjectIdentity[] objects) throws NotFoundException;

    /**
     * Obtains all the <code>Acl</code>s that apply for the passed <code>Object</code>s, but only for the
     * security identifies passed.<p>Implementations <em>MAY</em> provide a subset of the ACLs via this method
     * although this is NOT a requirement. This is intended to allow performance optimisations within implementations.
     * Callers should therefore use this method in preference to the alternative overloaded version which does not
     * have performance optimisation opportunities.</p>
     *  <p>The returned map is keyed on the passed objects, with the values being the <code>Acl</code>
     * instances. Any unknown objects (or objects for which the interested <code>Sid</code>s do not have entries) will
     * not have a map key.</p>
     *
     * @param objects the objects to find ACL information for
     * @param sids the security identities for which ACL information is required (may be <code>null</code> to denote
     *        all entries)
     *
     * @return a map with zero or more elements (never <code>null</code>)
     *
     * @throws NotFoundException DOCUMENT ME!
     */
    Map readAclsById(ObjectIdentity[] objects, Sid[] sids)
        throws NotFoundException;
}
