package org.acegisecurity.acls.jdbc;

import org.acegisecurity.acls.domain.AclImpl;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;

/**
 * A caching layer for {@link JdbcAclService}.
 * 
 * @author Ben Alex
 * @version $Id$
 *
 */
public interface AclCache {
	public AclImpl getFromCache(ObjectIdentity objectIdentity);
	public AclImpl getFromCache(Long pk);
	public void putInCache(AclImpl acl); // should walk tree as well!
	public void evictFromCache(Long pk);
}
