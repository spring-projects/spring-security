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
package org.springframework.security.acls.model;


import java.util.List;
import java.util.Map;


/**
 * Provides retrieval of {@link Acl} instances.
 *
 * @author Ben Alex
 */
public interface AclService {
    //~ Methods ========================================================================================================

    /**
     * Locates all object identities that use the specified parent.  This is useful for administration tools.
     *
     * @param parentIdentity to locate children of
     *
     * @return the children (or <tt>null</tt> if none were found)
     */
    List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity);

    /**
     * Same as {@link #readAclsById(Java.util.List<ObjectIdentity>)} except it returns only a single Acl.
     * <p>
     * This method should not be called as it does not leverage the underlying implementation's potential ability to
     * filter <tt>Acl</tt> entries based on a {@link Sid} parameter.</p>
     *
     * @param object to locate an {@link Acl} for
     *
     * @return the {@link Acl} for the requested {@link ObjectIdentity} (never <tt>null</tt>)
     *
     * @throws NotFoundException if an {@link Acl} was not found for the requested {@link ObjectIdentity}
     */
    Acl readAclById(ObjectIdentity object) throws NotFoundException;

    /**
     * Same as {@link #readAclsById(List, List)} except it returns only a single Acl.
     *
     * @param object to locate an {@link Acl} for
     * @param sids the security identities for which  {@link Acl} information is required
     *        (may be <tt>null</tt> to denote all entries)
     *
     * @return the {@link Acl} for the requested {@link ObjectIdentity} (never <tt>null</tt>)
     *
     * @throws NotFoundException if an {@link Acl} was not found for the requested {@link ObjectIdentity}
     */
    Acl readAclById(ObjectIdentity object, List<Sid> sids) throws NotFoundException;

    /**
     * Obtains all the <tt>Acl</tt>s that apply for the passed <tt>Object</tt>s.<p>The returned map is
     * keyed on the passed objects, with the values being the <tt>Acl</tt> instances. Any unknown objects will not
     * have a map key.</p>
     *
     * @param objects the objects to find {@link Acl} information for
     *
     * @return a map with exactly one element for each {@link ObjectIdentity} passed as an argument (never <tt>null</tt>)
     *
     * @throws NotFoundException if an {@link Acl} was not found for each requested {@link ObjectIdentity}
     */
    Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects) throws NotFoundException;

    /**
     * Obtains all the <tt>Acl</tt>s that apply for the passed <tt>Object</tt>s, but only for the
     * security identifies passed.<p>Implementations <em>MAY</em> provide a subset of the ACLs via this method
     * although this is NOT a requirement. This is intended to allow performance optimisations within implementations.
     * Callers should therefore use this method in preference to the alternative overloaded version which does not
     * have performance optimisation opportunities.</p>
     *  <p>The returned map is keyed on the passed objects, with the values being the <tt>Acl</tt>
     * instances. Any unknown objects (or objects for which the interested <tt>Sid</tt>s do not have entries) will
     * not have a map key.</p>
     *
     * @param objects the objects to find {@link Acl} information for
     * @param sids the security identities for which  {@link Acl} information is required
     *        (may be <tt>null</tt> to denote all entries)
     *
     * @return a map with exactly one element for each {@link ObjectIdentity} passed as an argument (never <tt>null</tt>)
     *
     * @throws NotFoundException if an {@link Acl} was not found for each requested {@link ObjectIdentity}
     */
    Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) throws NotFoundException;
}
