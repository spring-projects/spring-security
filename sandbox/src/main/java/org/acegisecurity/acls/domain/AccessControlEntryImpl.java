package org.acegisecurity.acls.domain;

import java.io.Serializable;

import org.acegisecurity.acls.AccessControlEntry;
import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.AuditableAccessControlEntry;
import org.acegisecurity.acls.Permission;
import org.acegisecurity.acls.sid.Sid;
import org.springframework.util.Assert;

/**
 * An immutable default implementation of <code>AccessControlEntry</code>.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public class AccessControlEntryImpl implements AccessControlEntry, AuditableAccessControlEntry {
	private Serializable id;
	private Acl acl;
	private Sid sid;
	private Permission permission;
	private boolean granting;
	private boolean auditSuccess = false;
	private boolean auditFailure = false;
	private boolean aceDirty = false;
	
	public void clearDirtyFlags() {
		this.aceDirty = false;
	}
	
	public boolean equals(Object arg0) {
		if (!(arg0 instanceof AccessControlEntryImpl)) {
			return false;
		}
		AccessControlEntryImpl rhs = (AccessControlEntryImpl) arg0;
		if (this.aceDirty != rhs.isAceDirty() ||
			this.auditFailure != rhs.isAuditFailure() ||
			this.auditSuccess != rhs.isAuditSuccess() ||
			this.granting != rhs.isGranting() ||
			!this.acl.equals(rhs.getAcl()) ||
			!this.id.equals(rhs.getId()) ||
			!this.permission.equals(rhs.getPermission()) ||
			!this.sid.equals(rhs.getSid()) ) {
			return false;
		}
		return true;
	}



	public AccessControlEntryImpl(Serializable id, Acl acl, Sid sid, Permission permission, boolean granting, boolean auditSuccess, boolean auditFailure) {
		Assert.notNull(acl, "Acl required");
		Assert.notNull(sid, "Sid required");
		Assert.notNull(permission, "Permission required");
		this.id = id;
		this.acl = acl; // can be null
		this.sid = sid;
		this.permission = permission;
		this.granting = granting;
		this.auditSuccess = auditSuccess;
		this.auditFailure = auditFailure;
	}
	
	public Acl getAcl() {
		return acl;
	}
	public boolean isGranting() {
		return granting;
	}
	public Serializable getId() {
		return id;
	}
	public Permission getPermission() {
		return permission;
	}
	public Sid getSid() {
		return sid;
	}
	
	void setPermission(Permission permission) {
		Assert.notNull(permission, "Permission required");
		this.permission = permission;
		this.aceDirty = true;
	}
	
	void setId(Serializable id) {
		this.id = id;
	}
	
	public boolean isAuditFailure() {
		return auditFailure;
	}

	void setAuditFailure(boolean auditFailure) {
		this.auditFailure = auditFailure;
		this.aceDirty = true;
	}

	public boolean isAuditSuccess() {
		return auditSuccess;
	}

	void setAuditSuccess(boolean auditSuccess) {
		this.auditSuccess = auditSuccess;
		this.aceDirty = true;
	}
	
	public boolean isAceDirty() {
		return aceDirty;
	}
	

	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("AccessControlEntryImpl[");
		sb.append("id: ").append(this.id).append("; ");
		sb.append("granting: ").append(this.granting).append("; ");
		sb.append("sid: ").append(this.sid).append("; ");
		sb.append("permission: ").append(this.permission);
		sb.append("]");
		return sb.toString();
	}	
}
