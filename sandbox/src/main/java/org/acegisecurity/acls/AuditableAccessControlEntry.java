package org.acegisecurity.acls;

/**
 * Represents an ACE that provides auditing information.
 * 
 * @author Ben Alex
 * @version $Id$
 *
 */
public interface AuditableAccessControlEntry extends AccessControlEntry {
	public boolean isAuditSuccess();
	public boolean isAuditFailure();
}
