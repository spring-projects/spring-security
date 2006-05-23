package org.acegisecurity.acls.jdbc;

import java.util.Map;

import javax.sql.DataSource;

import org.acegisecurity.acls.AclService;
import org.acegisecurity.acls.NotFoundException;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.sid.Sid;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.Assert;

/**
 * Simple JDBC-based implementation of <code>AclService</code>.
 * 
 * <p>
 * Requires the "dirty" flags in {@link org.acegisecurity.acls.domain.AclImpl} and {@link org.acegisecurity.acls.domain.AccessControlEntryImpl}
 * to be set, so that the implementation can detect changed parameters easily.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public class JdbcAclService implements AclService/*, MutableAclService */ {

	private AclCache aclCache;
	private JdbcTemplate template;
	private LookupStrategy lookupStrategy;

	public JdbcAclService(DataSource dataSource, AclCache aclCache, LookupStrategy lookupStrategy) {
        Assert.notNull(dataSource, "DataSource required");
        Assert.notNull(aclCache, "AclCache required");
		Assert.notNull(lookupStrategy, "LookupStrategy required");
		this.template = new JdbcTemplate(dataSource);
		this.aclCache = aclCache;
		this.lookupStrategy = lookupStrategy;
	}
	
	public Map readAclsById(ObjectIdentity[] objects) {
		return readAclsById(objects, null);
	}

	/**
	 * Method required by interface.
	 */
	public Map readAclsById(ObjectIdentity[] objects, Sid[] sids) throws NotFoundException {
		return lookupStrategy.readAclsById(objects, sids);
	}
	

}
