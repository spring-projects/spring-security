package org.acegisecurity.acls;

import java.io.Serializable;

import org.acegisecurity.acls.sid.Sid;

/**
 * Represents an individual permission assignment within an {@link Acl}. 
 * 
 * <p>
 * Instances MUST be immutable, as they are returned by <code>Acl</code>
 * and should not allow client modification.
 * 
 * @author Ben Alex
 * @version $Id$
 *
 */
public interface AccessControlEntry {
    /**
     * Obtains an identifier that represents this ACE.
     *
     * @return the identifier, or <code>null</code> if unsaved
     */
    public Serializable getId();
    
	public Acl getAcl();
	public Sid getSid();
	public Permission getPermission();
	public boolean isGranting();
}
