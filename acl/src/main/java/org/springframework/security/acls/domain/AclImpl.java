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
package org.springframework.security.acls.domain;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AuditableAcl;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.OwnershipAcl;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.UnloadedSidException;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.sid.Sid;
import org.springframework.util.Assert;


/**
 * Base implementation of <code>Acl</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AclImpl implements Acl, MutableAcl, AuditableAcl, OwnershipAcl {
    //~ Instance fields ================================================================================================

    private Acl parentAcl;
    private transient AclAuthorizationStrategy aclAuthorizationStrategy;
    private transient AuditLogger auditLogger;
    private List<AccessControlEntry> aces = new ArrayList<AccessControlEntry>();
    private ObjectIdentity objectIdentity;
    private Serializable id;
    private Sid owner; // OwnershipAcl
    private List<Sid> loadedSids = null; // includes all SIDs the WHERE clause covered, even if there was no ACE for a SID
    private boolean entriesInheriting = true;

    //~ Constructors ===================================================================================================

    /**
     * Minimal constructor, which should be used {@link
     * org.springframework.security.acls.MutableAclService#createAcl(ObjectIdentity)}.
     *
     * @param objectIdentity the object identity this ACL relates to (required)
     * @param id the primary key assigned to this ACL (required)
     * @param aclAuthorizationStrategy authorization strategy (required)
     * @param auditLogger audit logger (required)
     */
    public AclImpl(ObjectIdentity objectIdentity, Serializable id, AclAuthorizationStrategy aclAuthorizationStrategy,
                    AuditLogger auditLogger) {
        Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(id, "Id required");
        Assert.notNull(aclAuthorizationStrategy, "AclAuthorizationStrategy required");
        Assert.notNull(auditLogger, "AuditLogger required");
        this.objectIdentity = objectIdentity;
        this.id = id;
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
        this.auditLogger = auditLogger;
    }

    /**
     * Full constructor, which should be used by persistence tools that do not
     * provide field-level access features.
     *
     * @param objectIdentity the object identity this ACL relates to (required)
     * @param id the primary key assigned to this ACL (required)
     * @param aclAuthorizationStrategy authorization strategy (required)
     * @param auditLogger audit logger (required)
     * @param parentAcl the parent (may be <code>null</code>)
     * @param loadedSids the loaded SIDs if only a subset were loaded (may be
     *        <code>null</code>)
     * @param entriesInheriting if ACEs from the parent should inherit into
     *        this ACL
     * @param owner the owner (required)
     */
    public AclImpl(ObjectIdentity objectIdentity, Serializable id, AclAuthorizationStrategy aclAuthorizationStrategy,
                    AuditLogger auditLogger, Acl parentAcl, List<Sid> loadedSids, boolean entriesInheriting, Sid owner) {
        Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(id, "Id required");
        Assert.notNull(aclAuthorizationStrategy, "AclAuthorizationStrategy required");
        Assert.notNull(owner, "Owner required");
        Assert.notNull(auditLogger, "AuditLogger required");
        this.objectIdentity = objectIdentity;
        this.id = id;
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
        this.auditLogger = auditLogger;
        this.parentAcl = parentAcl; // may be null
        this.loadedSids = loadedSids; // may be null
        this.entriesInheriting = entriesInheriting;
        this.owner = owner;
    }

    /**
     * Private no-argument constructor for use by reflection-based persistence
     * tools along with field-level access.
     */
    @SuppressWarnings("unused")
    private AclImpl() {}

    //~ Methods ========================================================================================================

    public void deleteAce(int aceIndex) throws NotFoundException {
        aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
        verifyAceIndexExists(aceIndex);

        synchronized (aces) {
            this.aces.remove(aceIndex);
        }
    }

    private void verifyAceIndexExists(int aceIndex) {
        if (aceIndex < 0) {
            throw new NotFoundException("aceIndex must be greater than or equal to zero");
        }
        if (aceIndex >= this.aces.size()) {
            throw new NotFoundException("aceIndex must refer to an index of the AccessControlEntry list. " +
                    "List size is " + aces.size() + ", index was " + aceIndex);
        }
    }

    public void insertAce(int atIndexLocation, Permission permission, Sid sid, boolean granting) throws NotFoundException {
        aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
        Assert.notNull(permission, "Permission required");
        Assert.notNull(sid, "Sid required");
        if (atIndexLocation < 0) {
            throw new NotFoundException("atIndexLocation must be greater than or equal to zero");
        }
        if (atIndexLocation > this.aces.size()) {
            throw new NotFoundException("atIndexLocation must be less than or equal to the size of the AccessControlEntry collection");
        }

        AccessControlEntryImpl ace = new AccessControlEntryImpl(null, this, sid, permission, granting, false, false);

        synchronized (aces) {
            this.aces.add(atIndexLocation, ace);
        }
    }

    public List<AccessControlEntry> getEntries() {
        // Can safely return AccessControlEntry directly, as they're immutable outside the ACL package
        return new ArrayList<AccessControlEntry>(aces);
    }

    public Serializable getId() {
        return this.id;
    }

    public ObjectIdentity getObjectIdentity() {
        return objectIdentity;
    }

    public boolean isEntriesInheriting() {
        return entriesInheriting;
    }

    /**
     * Determines authorization.  The order of the <code>permission</code> and <code>sid</code> arguments is
     * <em>extremely important</em>! The method will iterate through each of the <code>permission</code>s in the order
     * specified. For each iteration, all of the <code>sid</code>s will be considered, again in the order they are
     * presented. A search will then be performed for the first {@link AccessControlEntry} object that directly
     * matches that <code>permission:sid</code> combination. When the <em>first full match</em> is found (ie an ACE
     * that has the SID currently being searched for and the exact permission bit mask being search for), the grant or
     * deny flag for that ACE will prevail. If the ACE specifies to grant access, the method will return
     * <code>true</code>. If the ACE specifies to deny access, the loop will stop and the next <code>permission</code>
     * iteration will be performed. If each permission indicates to deny access, the first deny ACE found will be
     * considered the reason for the failure (as it was the first match found, and is therefore the one most logically
     * requiring changes - although not always). If absolutely no matching ACE was found at all for any permission,
     * the parent ACL will be tried (provided that there is a parent and {@link #isEntriesInheriting()} is
     * <code>true</code>. The parent ACL will also scan its parent and so on. If ultimately no matching ACE is found,
     * a <code>NotFoundException</code> will be thrown and the caller will need to decide how to handle the permission
     * check. Similarly, if any of the SID arguments presented to the method were not loaded by the ACL,
     * <code>UnloadedSidException</code> will be thrown.
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
    public boolean isGranted(List<Permission> permission, List<Sid> sids, boolean administrativeMode)
            throws NotFoundException, UnloadedSidException {
        Assert.notEmpty(permission, "Permissions required");
        Assert.notEmpty(sids, "SIDs required");

        if (!this.isSidLoaded(sids)) {
            throw new UnloadedSidException("ACL was not loaded for one or more SID");
        }

        AccessControlEntry firstRejection = null;

        for (Permission p : permission) {
            for (Sid sid: sids) {
                // Attempt to find exact match for this permission mask and SID
                boolean scanNextSid = true;

                for (AccessControlEntry ace : aces ) {

                    if ((ace.getPermission().getMask() == p.getMask()) && ace.getSid().equals(sid)) {
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

                            break; // exit aces loop
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

    public boolean isSidLoaded(List<Sid> sids) {
        // If loadedSides is null, this indicates all SIDs were loaded
        // Also return true if the caller didn't specify a SID to find
        if ((this.loadedSids == null) || (sids == null) || (sids.size() == 0)) {
            return true;
        }

        // This ACL applies to a SID subset only. Iterate to check it applies.
        for (Sid sid: sids) {
            boolean found = false;

            for (Sid loadedSid : loadedSids) {
                if (sid.equals(loadedSid)) {
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

    public void setEntriesInheriting(boolean entriesInheriting) {
        aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
        this.entriesInheriting = entriesInheriting;
    }

    public void setOwner(Sid newOwner) {
        aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
        Assert.notNull(newOwner, "Owner required");
        this.owner = newOwner;
    }

    public Sid getOwner() {
        return this.owner;
    }

    public void setParent(Acl newParent) {
        aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
        Assert.isTrue(newParent == null || !newParent.equals(this), "Cannot be the parent of yourself");
        this.parentAcl = newParent;
    }

    public Acl getParentAcl() {
        return parentAcl;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("AclImpl[");
        sb.append("id: ").append(this.id).append("; ");
        sb.append("objectIdentity: ").append(this.objectIdentity).append("; ");
        sb.append("owner: ").append(this.owner).append("; ");

        int count = 0;

        for (AccessControlEntry ace : aces) {
            count++;

            if (count == 1) {
                sb.append("\r\n");
            }

            sb.append(ace).append("\r\n");
        }

        if (count == 0) {
            sb.append("no ACEs; ");
        }

        sb.append("inheriting: ").append(this.entriesInheriting).append("; ");
        sb.append("parent: ").append((this.parentAcl == null) ? "Null" : this.parentAcl.getObjectIdentity().toString());
        sb.append("aclAuthorizationStrategy: ").append(this.aclAuthorizationStrategy).append("; ");
        sb.append("auditLogger: ").append(this.auditLogger);
        sb.append("]");

        return sb.toString();
    }

    public void updateAce(int aceIndex, Permission permission)
        throws NotFoundException {
        aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
        verifyAceIndexExists(aceIndex);

        synchronized (aces) {
            AccessControlEntryImpl ace = (AccessControlEntryImpl) aces.get(aceIndex);
            ace.setPermission(permission);
        }
    }

    public void updateAuditing(int aceIndex, boolean auditSuccess, boolean auditFailure) {
        aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_AUDITING);
        verifyAceIndexExists(aceIndex);

        synchronized (aces) {
            AccessControlEntryImpl ace = (AccessControlEntryImpl) aces.get(aceIndex);
            ace.setAuditSuccess(auditSuccess);
            ace.setAuditFailure(auditFailure);
        }
    }

    public boolean equals(Object obj) {
        if (obj instanceof AclImpl) {
            AclImpl rhs = (AclImpl) obj;
            if (this.aces.equals(rhs.aces)) {
                if ((this.parentAcl == null && rhs.parentAcl == null) || (this.parentAcl.equals(rhs.parentAcl))) {
                    if ((this.objectIdentity == null && rhs.objectIdentity == null) || (this.objectIdentity.equals(rhs.objectIdentity))) {
                        if ((this.id == null && rhs.id == null) || (this.id.equals(rhs.id))) {
                            if ((this.owner == null && rhs.owner == null) || this.owner.equals(rhs.owner)) {
                                if (this.entriesInheriting == rhs.entriesInheriting) {
                                    if ((this.loadedSids == null && rhs.loadedSids == null)) {
                                        return true;
                                    }
                                    if (this.loadedSids.size() == rhs.loadedSids.size()) {
                                        for (int i = 0; i < this.loadedSids.size(); i++) {
                                            if (!this.loadedSids.get(i).equals(rhs.loadedSids.get(i))) {
                                                return false;
                                            }
                                        }
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

}
