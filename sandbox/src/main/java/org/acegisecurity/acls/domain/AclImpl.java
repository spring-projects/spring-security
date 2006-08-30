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

package org.acegisecurity.acls.domain;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;

import org.acegisecurity.acls.AccessControlEntry;
import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.AuditableAcl;
import org.acegisecurity.acls.MutableAcl;
import org.acegisecurity.acls.NotFoundException;
import org.acegisecurity.acls.OwnershipAcl;
import org.acegisecurity.acls.Permission;
import org.acegisecurity.acls.UnloadedSidException;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;

import org.acegisecurity.context.SecurityContextHolder;

import org.springframework.util.Assert;

import java.io.Serializable;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;


/**
 * Base implementation of <code>Acl</code>.
 *
 * @author Ben Alex
 * @version $Id
 */
public class AclImpl implements Acl, MutableAcl, AuditableAcl, OwnershipAcl {
    //~ Static fields/initializers =====================================================================================

    private static final int CHANGE_OWNERSHIP = 0;
    private static final int CHANGE_AUDITING = 1;
    private static final int CHANGE_GENERAL = 2;

    //~ Instance fields ================================================================================================

    private Acl parentAcl;
    private AuditLogger auditLogger = new ConsoleAuditLogger(); // AuditableAcl
    private GrantedAuthority gaGeneralChanges;
    private GrantedAuthority gaModifyAuditing;
    private GrantedAuthority gaTakeOwnership;
    private List aces = new Vector();
    private List deletedAces = new Vector();
    private Long id;
    private ObjectIdentity objectIdentity;
    private Sid owner; // OwnershipAcl
    private Sid[] loadedSids = null; // includes all SIDs the WHERE clause covered, even if there was no ACE for a SID
    private boolean aclDirty = false; // for snapshot detection
    private boolean addedAces = false; // for snapshot detection
    private boolean entriesInheriting = false;
    private boolean updatedAces = false; // for snapshot detection

    //~ Constructors ===================================================================================================

/**
     * Minimal constructor, which should be used {@link
     * org.acegisecurity.acls.MutableAclService#createAcl(ObjectIdentity)}.
     *
     * @param objectIdentity the object identity this ACL relates to (required)
     * @param id the primary key assigned to this ACL (required)
     * @param auths an array of <code>GrantedAuthority</code>s that have
     * special permissions (index 0 is the authority needed to change
     * ownership, index 1 is the authority needed to modify auditing details,
     * index 2 is the authority needed to change other ACL and ACE details) (required)
     */
    public AclImpl(ObjectIdentity objectIdentity, Long id, GrantedAuthority[] auths) {
        Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(id, "Id required");
        this.objectIdentity = objectIdentity;
        this.id = id;
        this.setAuthorities(auths);
    }

/**
     * Full constructor, which should be used by persistence tools that do not
     * provide field-level access features.
     *
     * @param objectIdentity the object identity this ACL relates to (required)
     * @param id the primary key assigned to this ACL (required)
     * @param auths an array of <code>GrantedAuthority</code>s that have
     * special permissions (index 0 is the authority needed to change
     * ownership, index 1 is the authority needed to modify auditing details,
     * index 2 is the authority needed to change other ACL and ACE details) (required)
     * @param parentAcl the parent (may be <code>null</code>)
     * @param loadedSids the loaded SIDs if only a subset were loaded (may be
     *        <code>null</code>)
     * @param entriesInheriting if ACEs from the parent should inherit into
     *        this ACL
     * @param owner the owner (required)
     */
    public AclImpl(ObjectIdentity objectIdentity, Long id, Acl parentAcl, GrantedAuthority[] auths, Sid[] loadedSids,
        boolean entriesInheriting, Sid owner) {
        Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(id, "Id required");
        Assert.notNull(owner, "Owner required");
        this.objectIdentity = objectIdentity;
        this.id = id;
        setAuthorities(auths);
        this.parentAcl = parentAcl; // may be null
        this.loadedSids = loadedSids; // may be null
        this.entriesInheriting = entriesInheriting;
        this.owner = owner;
    }

/**
     * Private no-argument constructor for use by reflection-based persistence
     * tools along with field-level access.
     */
    private AclImpl() {}

    //~ Methods ========================================================================================================

    /**
     * Clears the dirty flags on the <code>Acl</code>, but not any associated ACEs.
     */
    public void clearDirtyFlags() {
        this.aclDirty = false;
        this.addedAces = false;
        this.updatedAces = false;
    }

    public void deleteAce(Long aceId) throws NotFoundException {
        securityCheck(CHANGE_GENERAL);

        synchronized (aces) {
            int offset = findAceOffset(aceId);

            if (offset == -1) {
                throw new NotFoundException("Requested ACE ID not found");
            }

            aces.remove(offset);
            deletedAces.add(aceId);
        }
    }

    private int findAceOffset(Long aceId) {
        Assert.notNull(aceId, "ACE ID is required");

        synchronized (aces) {
            for (int i = 0; i < aces.size(); i++) {
                AccessControlEntry ace = (AccessControlEntry) aces.get(i);

                if (ace.getId().equals(aceId)) {
                    return i;
                }
            }
        }

        return -1;
    }

    public AccessControlEntry[] getEntries() {
        // Can safely return AccessControlEntry directly, as they're immutable
        return (AccessControlEntry[]) aces.toArray(new AccessControlEntry[] {});
    }

    public Serializable getId() {
        return this.id;
    }

    public ObjectIdentity getObjectIdentity() {
        return objectIdentity;
    }

    public Sid getOwner() {
        return this.owner;
    }

    public Acl getParentAcl() {
        return parentAcl;
    }

    public void insertAce(Long afterAceId, Permission permission, Sid sid, boolean granting)
        throws NotFoundException {
        securityCheck(CHANGE_GENERAL);
        Assert.notNull(permission, "Permission required");
        Assert.notNull(sid, "Sid required");

        AccessControlEntryImpl ace = new AccessControlEntryImpl(null, this, sid, permission, granting, false, false);

        synchronized (aces) {
            if (afterAceId != null) {
                int offset = findAceOffset(afterAceId);

                if (offset == -1) {
                    throw new NotFoundException("Requested ACE ID not found");
                }

                aces.add(offset + 1, ace);
            } else {
                aces.add(ace);
            }
        }

        this.addedAces = true;
    }

    public boolean isAclDirty() {
        return aclDirty;
    }

    public boolean isEntriesInheriting() {
        return entriesInheriting;
    }

    /**
     * Determines authorization.  The order of the <code>permission</code> and <code>sid</code> arguments is
     * <em>extremely important</em>! The method will iterate through each of the <code>permission</code>s in the order
     * specified. For each iteration, all of the <code>sid</code>s will be considered, again in the order they are
     * presented. The iteration of each <code>permission:sid</code> combination will then inspect the ACEs in the
     * order they appear in the ACL. When the <em>first full match</em> is found (ie an ACE that has the SID currently
     * being searched for and the exact permission bit mask being search for), the grant or deny flag for that ACE
     * will prevail. If the ACE specifies to grant access, the method will return <code>true</code>. If the ACE
     * specifies to deny access, the loop will stop and the next <code>permission</code> iteration will be performed.
     * If each permission indicates to deny access, the first deny ACE found will be considered the reason for the
     * failure (as it was the first match found, and is therefore the one most logically requiring changes - although
     * not always). If absolutely no matching ACE was found at all for any permission, the parent ACL will be tried
     * (provided that there is a parent and {@link #isEntriesInheriting()} is <code>true</code>. The parent ACL will
     * also scan its parent and so on. If ultimately no matching ACE is found, a <code>NotFoundException</code> will
     * be thrown and the caller will need to decide how to handle the permission check. Similarly, if any of the
     * passed SIDs were not loaded by the ACL, the <code>UnloadedSidException</code> will be thrown.
     *
     * @param permission the exact permissions to scan for (order is important)
     * @param sids the exact SIDs to scan for (order is important)
     * @param administrativeMode if <code>true</code> denotes the query is for administrative purposes and no auditing
     *        will be undertaken
     *
     * @return <code>true</code> if one of the permissions has been granted, <code>false</code> if one of the
     *         permissions has been specifically revoked
     *
     * @throws NotFoundException if an exact ACE for one of the permission bit masks and SID combination could not be
     *         found
     * @throws UnloadedSidException if the passed SIDs are unknown to this ACL because the ACL was only loaded for a
     *         subset of SIDs
     */
    public boolean isGranted(Permission[] permission, Sid[] sids, boolean administrativeMode)
        throws NotFoundException, UnloadedSidException {
        Assert.notEmpty(permission, "Permissions required");
        Assert.notEmpty(sids, "SIDs required");

        if (!this.isSidLoaded(sids)) {
            throw new UnloadedSidException("ACL was not loaded for one or more SID");
        }

        AccessControlEntry firstRejection = null;

        for (int i = 0; i < permission.length; i++) {
            for (int x = 0; x < sids.length; x++) {
                // Attempt to find exact match for this permission mask and SID
                Iterator acesIterator = aces.iterator();
                boolean scanNextSid = true;

                while (acesIterator.hasNext()) {
                    AccessControlEntry ace = (AccessControlEntry) acesIterator.next();

                    if ((ace.getPermission().getMask() == permission[i].getMask()) && ace.getSid().equals(sids[x])) {
                        // Found a matching ACE, so its authorization decision will prevail
                        if (ace.isGranting()) {
                            // Success
                            if (!administrativeMode) {
                                auditLogger.logIfNeeded(true, ace);
                            }

                            return true;
                        } else {
                            // Failure for this permission, so stop search
                            // We will see if they have a different permission
                            // (this permission is 100% rejected for this SID)
                            if (firstRejection == null) {
                                // Store first rejection for auditing reasons
                                firstRejection = ace;
                            }

                            scanNextSid = false; // helps break the loop

                            break; // exit "aceIterator" while loop
                        }
                    }
                }

                if (!scanNextSid) {
                    break; // exit SID for loop (now try next permission)
                }
            }
        }

        if (firstRejection != null) {
            // We found an ACE to reject the request at this point, as no
            // other ACEs were found that granted a different permission
            if (!administrativeMode) {
                auditLogger.logIfNeeded(false, firstRejection);
            }

            return false;
        }

        // No matches have been found so far
        if (isEntriesInheriting() && (parentAcl != null)) {
            // We have a parent, so let them try to find a matching ACE
            return parentAcl.isGranted(permission, sids, false);
        } else {
            // We either have no parent, or we're the uppermost parent
            throw new NotFoundException("Unable to locate a matching ACE for passed permissions and SIDs");
        }
    }

    public boolean isSidLoaded(Sid[] sids) {
        // If loadedSides is null, this indicates all SIDs were loaded
        // Also return true if the caller didn't specify a SID to find
        if ((this.loadedSids == null) || (sids == null) || (sids.length == 0)) {
            return true;
        }

        // This ACL applies to a SID subset. Iterate to check it applies
        for (int i = 0; i < sids.length; i++) {
            boolean found = false;

            for (int y = 0; y < this.loadedSids.length; y++) {
                if (sids[i].equals(this.loadedSids[y])) {
                    // this SID is OK
                    found = true;

                    break; // out of loadedSids for loop
                }
            }

            if (!found) {
                return false;
            }
        }

        return true;
    }

    protected void securityCheck(int changeType) {
        if ((SecurityContextHolder.getContext() == null)
            || (SecurityContextHolder.getContext().getAuthentication() == null)
            || !SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            throw new AccessDeniedException("Authenticated principal required to operate with ACLs");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Check if authorized by virtue of ACL ownership
        Sid currentUser = new PrincipalSid(authentication);

        if (currentUser.equals(this.owner) && ((changeType == CHANGE_GENERAL) || (changeType == CHANGE_OWNERSHIP))) {
            return;
        }

        // Not authorized by ACL ownership; try via adminstrative permissions
        GrantedAuthority requiredAuthority = null;

        if (changeType == CHANGE_AUDITING) {
            requiredAuthority = this.gaModifyAuditing;
        } else if (changeType == CHANGE_GENERAL) {
            requiredAuthority = this.gaGeneralChanges;
        } else if (changeType == CHANGE_OWNERSHIP) {
            requiredAuthority = this.gaTakeOwnership;
        } else {
            throw new IllegalArgumentException("Unknown change type");
        }

        // Iterate this principal's authorities to determine right
        GrantedAuthority[] auths = authentication.getAuthorities();

        for (int i = 0; i < auths.length; i++) {
            if (requiredAuthority.equals(auths[i])) {
                return;
            }
        }

        throw new AccessDeniedException(
            "Principal does not have required ACL permissions to perform requested operation");
    }

    /**
     * Change the special adminstrative permissions honoured by this object.<p>Normally a principal must be the
     * owner of the ACL in order to make most changes. The authorities passed to this method provide a way for
     * non-owners to modify the ACL (and indeed modify audit parameters, which are not available to ACL owners).</p>
     *
     * @param auths an array of <code>GrantedAuthority</code>s that have administrative permissions (index 0 is the
     *        authority needed to change ownership, index 1 is the authority needed to modify auditing details, index
     *        2 is the authority needed to change other ACL and ACE details)
     */
    private void setAuthorities(GrantedAuthority[] auths) {
        Assert.notEmpty(auths, "GrantedAuthority[] with three elements required");
        Assert.isTrue(auths.length == 3, "GrantedAuthority[] with three elements required");
        this.gaTakeOwnership = auths[0];
        this.gaModifyAuditing = auths[1];
        this.gaGeneralChanges = auths[2];
    }

    public void setEntriesInheriting(boolean entriesInheriting) {
        securityCheck(CHANGE_GENERAL);
        this.entriesInheriting = entriesInheriting;
        this.aclDirty = true;
    }

    public void setOwner(Sid newOwner) {
        securityCheck(CHANGE_OWNERSHIP);
        Assert.notNull(newOwner, "Owner required");
        this.owner = newOwner;
        this.aclDirty = true;
    }

    public void setParent(MutableAcl newParent) {
        securityCheck(CHANGE_GENERAL);
        Assert.notNull(newParent, "New Parent required");
        this.parentAcl = newParent;
        this.aclDirty = true;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("AclImpl[");
        sb.append("id: ").append(this.id).append("; ");
        sb.append("objectIdentity: ").append(this.objectIdentity).append("; ");
        sb.append("owner: ").append(this.owner).append("; ");

        Iterator iterator = this.aces.iterator();
        int count = 0;

        while (iterator.hasNext()) {
            count++;

            if (count == 1) {
                sb.append("\r\n");
            }

            sb.append(iterator.next().toString()).append("\r\n");
        }

        sb.append("inheriting: ").append(this.entriesInheriting).append("; ");
        sb.append("parent: ").append((this.parentAcl == null) ? "Null" : this.parentAcl.getObjectIdentity());
        sb.append("]");

        return sb.toString();
    }

    public void updateAce(Long aceId, Permission permission)
        throws NotFoundException {
        securityCheck(CHANGE_GENERAL);

        synchronized (aces) {
            int offset = findAceOffset(aceId);

            if (offset == 1) {
                throw new NotFoundException("Requested ACE ID not found");
            }

            AccessControlEntryImpl ace = (AccessControlEntryImpl) aces.get(offset);
            ace.setPermission(permission);
        }

        this.updatedAces = true;
    }

    public void updateAuditing(Long aceId, boolean auditSuccess, boolean auditFailure) {
        securityCheck(CHANGE_AUDITING);

        synchronized (aces) {
            int offset = findAceOffset(aceId);

            if (offset == 1) {
                throw new NotFoundException("Requested ACE ID not found");
            }

            AccessControlEntryImpl ace = (AccessControlEntryImpl) aces.get(offset);
            ace.setAuditSuccess(auditSuccess);
            ace.setAuditFailure(auditFailure);
        }

        this.updatedAces = true;
    }
}
