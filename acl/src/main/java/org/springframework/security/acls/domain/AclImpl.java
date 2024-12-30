/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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

import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AuditableAcl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.OwnershipAcl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.UnloadedSidException;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * Base implementation of <code>Acl</code>.
 *
 * @author Ben Alex
 */
public class AclImpl implements Acl, MutableAcl, AuditableAcl, OwnershipAcl {

	private Acl parentAcl;

	private transient AclAuthorizationStrategy aclAuthorizationStrategy;

	private transient PermissionGrantingStrategy permissionGrantingStrategy;

	private final List<AccessControlEntry> aces = new ArrayList<>();

	private ObjectIdentity objectIdentity;

	private Serializable id;

	// OwnershipAcl
	private Sid owner;

	// includes all SIDs the WHERE clause covered, even if there was no ACE for a SID
	private List<Sid> loadedSids = null;

	private boolean entriesInheriting = true;

	/**
	 * Minimal constructor, which should be used
	 * {@link org.springframework.security.acls.model.MutableAclService#createAcl(ObjectIdentity)}
	 * .
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
		this.permissionGrantingStrategy = new DefaultPermissionGrantingStrategy(auditLogger);
	}

	/**
	 * Full constructor, which should be used by persistence tools that do not provide
	 * field-level access features.
	 * @param objectIdentity the object identity this ACL relates to
	 * @param id the primary key assigned to this ACL
	 * @param aclAuthorizationStrategy authorization strategy
	 * @param grantingStrategy the {@code PermissionGrantingStrategy} which will be used
	 * by the {@code isGranted()} method
	 * @param parentAcl the parent (may be may be {@code null})
	 * @param loadedSids the loaded SIDs if only a subset were loaded (may be {@code null}
	 * )
	 * @param entriesInheriting if ACEs from the parent should inherit into this ACL
	 * @param owner the owner (required)
	 */
	public AclImpl(ObjectIdentity objectIdentity, Serializable id, AclAuthorizationStrategy aclAuthorizationStrategy,
			PermissionGrantingStrategy grantingStrategy, Acl parentAcl, List<Sid> loadedSids, boolean entriesInheriting,
			Sid owner) {
		Assert.notNull(objectIdentity, "Object Identity required");
		Assert.notNull(id, "Id required");
		Assert.notNull(aclAuthorizationStrategy, "AclAuthorizationStrategy required");
		Assert.notNull(owner, "Owner required");
		this.objectIdentity = objectIdentity;
		this.id = id;
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
		this.parentAcl = parentAcl; // may be null
		this.loadedSids = loadedSids; // may be null
		this.entriesInheriting = entriesInheriting;
		this.owner = owner;
		this.permissionGrantingStrategy = grantingStrategy;
	}

	/**
	 * Private no-argument constructor for use by reflection-based persistence tools along
	 * with field-level access.
	 */
	@SuppressWarnings("unused")
	private AclImpl() {
	}

	@Override
	public void deleteAce(int aceIndex) throws NotFoundException {
		this.aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		verifyAceIndexExists(aceIndex);
		synchronized (this.aces) {
			this.aces.remove(aceIndex);
		}
	}

	private void verifyAceIndexExists(int aceIndex) {
		if (aceIndex < 0) {
			throw new NotFoundException("aceIndex must be greater than or equal to zero");
		}
		if (aceIndex >= this.aces.size()) {
			throw new NotFoundException("aceIndex must refer to an index of the AccessControlEntry list. "
					+ "List size is " + this.aces.size() + ", index was " + aceIndex);
		}
	}

	@Override
	public void insertAce(int atIndexLocation, Permission permission, Sid sid, boolean granting)
			throws NotFoundException {
		this.aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		Assert.notNull(permission, "Permission required");
		Assert.notNull(sid, "Sid required");
		if (atIndexLocation < 0) {
			throw new NotFoundException("atIndexLocation must be greater than or equal to zero");
		}
		if (atIndexLocation > this.aces.size()) {
			throw new NotFoundException(
					"atIndexLocation must be less than or equal to the size of the AccessControlEntry collection");
		}
		AccessControlEntryImpl ace = new AccessControlEntryImpl(null, this, sid, permission, granting, false, false);
		synchronized (this.aces) {
			this.aces.add(atIndexLocation, ace);
		}
	}

	@Override
	public List<AccessControlEntry> getEntries() {
		// Can safely return AccessControlEntry directly, as they're immutable outside the
		// ACL package
		return new ArrayList<>(this.aces);
	}

	@Override
	public Serializable getId() {
		return this.id;
	}

	@Override
	public ObjectIdentity getObjectIdentity() {
		return this.objectIdentity;
	}

	@Override
	public boolean isEntriesInheriting() {
		return this.entriesInheriting;
	}

	/**
	 * Delegates to the {@link PermissionGrantingStrategy}.
	 * @throws UnloadedSidException if the passed SIDs are unknown to this ACL because the
	 * ACL was only loaded for a subset of SIDs
	 * @see DefaultPermissionGrantingStrategy
	 */
	@Override
	public boolean isGranted(List<Permission> permission, List<Sid> sids, boolean administrativeMode)
			throws NotFoundException, UnloadedSidException {
		Assert.notEmpty(permission, "Permissions required");
		Assert.notEmpty(sids, "SIDs required");
		if (!this.isSidLoaded(sids)) {
			throw new UnloadedSidException("ACL was not loaded for one or more SID");
		}
		return this.permissionGrantingStrategy.isGranted(this, permission, sids, administrativeMode);
	}

	@Override
	public boolean isSidLoaded(List<Sid> sids) {
		// If loadedSides is null, this indicates all SIDs were loaded
		// Also return true if the caller didn't specify a SID to find
		if ((this.loadedSids == null) || (sids == null) || sids.isEmpty()) {
			return true;
		}

		// This ACL applies to a SID subset only. Iterate to check it applies.
		for (Sid sid : sids) {
			boolean found = false;
			for (Sid loadedSid : this.loadedSids) {
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

	@Override
	public void setEntriesInheriting(boolean entriesInheriting) {
		this.aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		this.entriesInheriting = entriesInheriting;
	}

	@Override
	public void setOwner(Sid newOwner) {
		this.aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
		Assert.notNull(newOwner, "Owner required");
		this.owner = newOwner;
	}

	@Override
	public Sid getOwner() {
		return this.owner;
	}

	@Override
	public void setParent(Acl newParent) {
		this.aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		Assert.isTrue(newParent == null || !newParent.equals(this), "Cannot be the parent of yourself");
		this.parentAcl = newParent;
	}

	@Override
	public Acl getParentAcl() {
		return this.parentAcl;
	}

	@Override
	public void updateAce(int aceIndex, Permission permission) throws NotFoundException {
		this.aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		verifyAceIndexExists(aceIndex);
		synchronized (this.aces) {
			AccessControlEntryImpl ace = (AccessControlEntryImpl) this.aces.get(aceIndex);
			ace.setPermission(permission);
		}
	}

	@Override
	public void updateAuditing(int aceIndex, boolean auditSuccess, boolean auditFailure) {
		this.aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_AUDITING);
		verifyAceIndexExists(aceIndex);
		synchronized (this.aces) {
			AccessControlEntryImpl ace = (AccessControlEntryImpl) this.aces.get(aceIndex);
			ace.setAuditSuccess(auditSuccess);
			ace.setAuditFailure(auditFailure);
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || !(obj instanceof AclImpl)) {
			return false;
		}
		AclImpl other = (AclImpl) obj;
		boolean result = true;
		result = result && this.aces.equals(other.aces);
		result = result && ObjectUtils.nullSafeEquals(this.parentAcl, other.parentAcl);
		result = result && ObjectUtils.nullSafeEquals(this.objectIdentity, other.objectIdentity);
		result = result && ObjectUtils.nullSafeEquals(this.id, other.id);
		result = result && ObjectUtils.nullSafeEquals(this.owner, other.owner);
		result = result && this.entriesInheriting == other.entriesInheriting;
		result = result && ObjectUtils.nullSafeEquals(this.loadedSids, other.loadedSids);
		return result;
	}

	@Override
	public int hashCode() {
		int result = (this.parentAcl != null) ? this.parentAcl.hashCode() : 0;
		result = 31 * result + this.aclAuthorizationStrategy.hashCode();
		result = 31 * result
				+ ((this.permissionGrantingStrategy != null) ? this.permissionGrantingStrategy.hashCode() : 0);
		result = 31 * result + ((this.aces != null) ? this.aces.hashCode() : 0);
		result = 31 * result + this.objectIdentity.hashCode();
		result = 31 * result + this.id.hashCode();
		result = 31 * result + ((this.owner != null) ? this.owner.hashCode() : 0);
		result = 31 * result + ((this.loadedSids != null) ? this.loadedSids.hashCode() : 0);
		result = 31 * result + (this.entriesInheriting ? 1 : 0);
		return result;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("AclImpl[");
		sb.append("id: ").append(this.id).append("; ");
		sb.append("objectIdentity: ").append(this.objectIdentity).append("; ");
		sb.append("owner: ").append(this.owner).append("; ");
		int count = 0;
		for (AccessControlEntry ace : this.aces) {
			count++;
			if (count == 1) {
				sb.append("\n");
			}
			sb.append(ace).append("\n");
		}
		if (count == 0) {
			sb.append("no ACEs; ");
		}
		sb.append("inheriting: ").append(this.entriesInheriting).append("; ");
		sb.append("parent: ").append((this.parentAcl == null) ? "Null" : this.parentAcl.getObjectIdentity().toString());
		sb.append("; ");
		sb.append("aclAuthorizationStrategy: ").append(this.aclAuthorizationStrategy).append("; ");
		sb.append("permissionGrantingStrategy: ").append(this.permissionGrantingStrategy);
		sb.append("]");
		return sb.toString();
	}

}
