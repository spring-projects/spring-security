package org.acegisecurity.acls.domain;

import org.acegisecurity.acls.AccessControlEntry;

/**
 * Used by <code>AclImpl</code> to log audit events.
 * 
 * @author Ben Alex
 * @version $Id$
 *
 */
public interface AuditLogger {
	public void logIfNeeded(boolean granted, AccessControlEntry ace);
}
