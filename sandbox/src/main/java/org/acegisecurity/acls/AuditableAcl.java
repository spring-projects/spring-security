package org.acegisecurity.acls;

/**
 * A mutable ACL that provides audit capabilities.
 * 
 * @author Ben Alex
 * @version $Id$
 *
 */
public interface AuditableAcl extends MutableAcl {
	public void updateAuditing(Long aceId, boolean auditSuccess, boolean auditFailure);
}
