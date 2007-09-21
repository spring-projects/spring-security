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

import java.io.Serializable;


/**
 * Represents an access control list (ACL) for a domain object.
 *
 * <p>
 * An <code>Acl</code> represents all ACL entries for a given domain object. In
 * order to avoid needing references to the domain object itself, this
 * interface handles indirection between a domain object and an ACL object
 * identity via the {@link
 * org.springframework.security.acls.objectidentity.ObjectIdentity} interface.
 * </p>
 *
 * <p>
 * An implementation represents the {@link org.springframework.security.acls.Permission}
 * list applicable for some or all {@link org.springframework.security.acls.sid.Sid}
 * instances.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface Acl extends Serializable {
    //~ Methods ========================================================================================================

    /**
     * Returns all of the entries represented by the present <code>Acl</code> (not parents).<p>This method is
     * typically used for administrative purposes.</p>
     *  <p>The order that entries appear in the array is unspecified. However, if implementations use
     * particular ordering logic in authorization decisions, the entries returned by this method <em>MUST</em> be
     * ordered in that manner.</p>
     *  <p>Do <em>NOT</em> use this method for making authorization decisions. Instead use {@link
     * #isGranted(Permission[], Sid[], boolean)}.</p>
     *  <p>This method must operate correctly even if the <code>Acl</code> only represents a subset of
     * <code>Sid</code>s. The caller is responsible for correctly handling the result if only a subset of
     * <code>Sid</code>s is represented.</p>
     *
     * @return the list of entries represented by the <code>Acl</code>
     */
    AccessControlEntry[] getEntries();

    /**
     * Obtains the domain object this <code>Acl</code> provides entries for. This is immutable once an
     * <code>Acl</code> is created.
     *
     * @return the object identity
     */
    ObjectIdentity getObjectIdentity();

    /**
     * Determines the owner of the <code>Acl</code>. The meaning of ownership varies by implementation and is
     * unspecified.
     *
     * @return the owner (may be null if the implementation does not use ownership concepts)
     */
    Sid getOwner();

    /**
     * A domain object may have a parent for the purpose of ACL inheritance. If there is a parent, its ACL can
     * be accessed via this method. In turn, the parent's parent (grandparent) can be accessed and so on.<p>This
     * method solely represents the presence of a navigation hierarchy between the parent <code>Acl</code> and this
     * <code>Acl</code>. For actual inheritance to take place, the {@link #isEntriesInheriting()} must also be
     * <code>true</code>.</p>
     *  <p>This method must operate correctly even if the <code>Acl</code> only represents a subset of
     * <code>Sid</code>s. The caller is responsible for correctly handling the result if only a subset of
     * <code>Sid</code>s is represented.</p>
     *
     * @return the parent <code>Acl</code>
     */
    Acl getParentAcl();

    /**
     * Indicates whether the ACL entries from the {@link #getParentAcl()} should flow down into the current
     * <code>Acl</code>.<p>The mere link between an <code>Acl</code> and a parent <code>Acl</code> on its own
     * is insufficient to cause ACL entries to inherit down. This is because a domain object may wish to have entirely
     * independent entries, but maintain the link with the parent for navigation purposes. Thus, this method denotes
     * whether or not the navigation relationship also extends to the actual inheritence of entries.</p>
     *
     * @return <code>true</code> if parent ACL entries inherit into the current <code>Acl</code>
     */
    boolean isEntriesInheriting();

    /**
     * This is the actual authorization logic method, and must be used whenever ACL authorization decisions are
     * required.<p>An array of <code>Sid</code>s are presented, representing security identifies of the current
     * principal. In addition, an array of <code>Permission</code>s is presented which will have one or more bits set
     * in order to indicate the permissions needed for an affirmative authorization decision. An array is presented
     * because holding <em>any</em> of the <code>Permission</code>s inside the array will be sufficient for an
     * affirmative authorization.</p>
     *  <p>The actual approach used to make authorization decisions is left to the implementation and is not
     * specified by this interface. For example, an implementation <em>MAY</em> search the current ACL in the order
     * the ACL entries have been stored. If a single entry is found that has the same active bits as are shown in a
     * passed <code>Permission</code>, that entry's grant or deny state may determine the authorization decision. If
     * the case of a deny state, the deny decision will only be relevant if all other <code>Permission</code>s passed
     * in the array have also been unsuccessfully searched. If no entry is found that match the bits in the current
     * ACL, provided that {@link #isEntriesInheriting()} is <code>true</code>, the authorization decision may be
     * passed to the parent ACL. If there is no matching entry, the implementation MAY throw an exception, or make a
     * predefined authorization decision.</p>
     *  <p>This method must operate correctly even if the <code>Acl</code> only represents a subset of
     * <code>Sid</code>s.</p>
     *
     * @param permission the permission or permissions required
     * @param sids the security identities held by the principal
     * @param administrativeMode if <code>true</code> denotes the query is for administrative purposes and no logging
     *        or auditing (if supported by the implementation) should be undertaken
     *
     * @return <code>true</code> is authorization is granted
     *
     * @throws NotFoundException MUST be thrown if an implementation cannot make an authoritative authorization
     *         decision, usually because there is no ACL information for this particular permission and/or SID
     * @throws UnloadedSidException thrown if the <code>Acl</code> does not have details for one or more of the
     *         <code>Sid</code>s passed as arguments
     */
    boolean isGranted(Permission[] permission, Sid[] sids, boolean administrativeMode)
        throws NotFoundException, UnloadedSidException;

    /**
     * For efficiency reasons an <code>Acl</code> may be loaded and <em>not</em> contain entries for every
     * <code>Sid</code> in the system. If an <code>Acl</code> has been loaded and does not represent every
     * <code>Sid</code>, all methods of the <code>Sid</code> can only be used within the limited scope of the
     * <code>Sid</code> instances it actually represents.
     * <p>
     * It is normal to load an <code>Acl</code> for only particular <code>Sid</code>s if read-only authorization
     * decisions are being made. However, if user interface reporting or modification of <code>Acl</code>s are
     * desired, an <code>Acl</code> should be loaded with all <code>Sid</code>s. This method denotes whether or
     * not the specified <code>Sid</code>s have been loaded or not.
     * </p>
     *
     * @param sids one or more security identities the caller is interest in knowing whether this <code>Sid</code>
     *        supports
     *
     * @return <code>true</code> if every passed <code>Sid</code> is represented by this <code>Acl</code> instance
     */
    boolean isSidLoaded(Sid[] sids);
}
