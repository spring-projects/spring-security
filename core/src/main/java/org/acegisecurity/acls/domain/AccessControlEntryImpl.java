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

import org.acegisecurity.acls.AccessControlEntry;
import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.AuditableAccessControlEntry;
import org.acegisecurity.acls.Permission;
import org.acegisecurity.acls.sid.Sid;

import org.springframework.util.Assert;

import java.io.Serializable;


/**
 * An immutable default implementation of <code>AccessControlEntry</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AccessControlEntryImpl implements AccessControlEntry, AuditableAccessControlEntry {
    //~ Instance fields ================================================================================================

    private Acl acl;
    private Permission permission;
    private Serializable id;
    private Sid sid;
    private boolean auditFailure = false;
    private boolean auditSuccess = false;
    private boolean granting;

    //~ Constructors ===================================================================================================

    public AccessControlEntryImpl(Serializable id, Acl acl, Sid sid, Permission permission, boolean granting,
        boolean auditSuccess, boolean auditFailure) {
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

    //~ Methods ========================================================================================================

    public boolean equals(Object arg0) {
        if (!(arg0 instanceof AccessControlEntryImpl)) {
            return false;
        }

        AccessControlEntryImpl rhs = (AccessControlEntryImpl) arg0;

        if ((this.auditFailure != rhs.isAuditFailure()) || (this.auditSuccess != rhs.isAuditSuccess())
            || (this.granting != rhs.isGranting()) || !this.acl.equals(rhs.getAcl()) || !this.id.equals(rhs.getId())
            || !this.permission.equals(rhs.getPermission()) || !this.sid.equals(rhs.getSid())) {
            return false;
        }

        return true;
    }

    public Acl getAcl() {
        return acl;
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

    public boolean isAuditFailure() {
        return auditFailure;
    }

    public boolean isAuditSuccess() {
        return auditSuccess;
    }

    public boolean isGranting() {
        return granting;
    }

    void setAuditFailure(boolean auditFailure) {
        this.auditFailure = auditFailure;
    }

    void setAuditSuccess(boolean auditSuccess) {
        this.auditSuccess = auditSuccess;
    }

    void setPermission(Permission permission) {
        Assert.notNull(permission, "Permission required");
        this.permission = permission;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("AccessControlEntryImpl[");
        sb.append("id: ").append(this.id).append("; ");
        sb.append("granting: ").append(this.granting).append("; ");
        sb.append("sid: ").append(this.sid).append("; ");
        sb.append("permission: ").append(this.permission).append("; ");
        sb.append("auditSuccess: ").append(this.auditSuccess).append("; ");
        sb.append("auditFailure: ").append(this.auditFailure);
        sb.append("]");

        return sb.toString();
    }
}
