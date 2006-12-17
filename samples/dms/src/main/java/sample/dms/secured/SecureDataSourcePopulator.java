package sample.dms.secured;

import javax.sql.DataSource;

import org.acegisecurity.acls.MutableAcl;
import org.acegisecurity.acls.MutableAclService;
import org.acegisecurity.acls.NotFoundException;
import org.acegisecurity.acls.Permission;
import org.acegisecurity.acls.domain.BasePermission;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityImpl;
import org.acegisecurity.acls.sid.GrantedAuthoritySid;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;
import org.acegisecurity.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.util.Assert;

import sample.dms.AbstractElement;
import sample.dms.DataSourcePopulator;
import sample.dms.DocumentDao;

public class SecureDataSourcePopulator extends DataSourcePopulator {

	private MutableAclService aclService;
	
	public SecureDataSourcePopulator(DataSource dataSource, SecureDocumentDao documentDao, PlatformTransactionManager platformTransactionManager, MutableAclService aclService) {
		super(dataSource, documentDao, platformTransactionManager);
		Assert.notNull(aclService, "MutableAclService required");
		this.aclService = aclService;
	}

	protected void addPermission(DocumentDao documentDao, AbstractElement element, String recipient, int level) {
		Assert.notNull(documentDao, "DocumentDao required");
		Assert.isInstanceOf(SecureDocumentDao.class, documentDao, "DocumentDao should have been a SecureDocumentDao");
		Assert.notNull(element, "Element required");
		Assert.hasText(recipient, "Recipient required");
		Assert.notNull(SecurityContextHolder.getContext().getAuthentication(), "SecurityContextHolder must contain an Authentication");
		
		// We need SecureDocumentDao to assign different permissions
		SecureDocumentDao dao = (SecureDocumentDao) documentDao;
		
		// We need to construct an ACL-specific Sid. Note the prefix contract is defined on the superclass method's JavaDocs
		Sid sid = null;
		if (recipient.startsWith("ROLE_")) {
			sid = new GrantedAuthoritySid(recipient);
		} else {
			sid = new PrincipalSid(recipient);
		}
		
		// We need to identify the target domain object and create an ObjectIdentity for it
		// This works because AbstractElement has a "getId()" method
		ObjectIdentity identity = new ObjectIdentityImpl(element);
		// ObjectIdentity identity = new ObjectIdentityImpl(element.getClass(), element.getId()); // equivalent
		
		// Next we need to create a Permission
		Permission permission = null;
		if (level == LEVEL_NEGATE_READ || level == LEVEL_GRANT_READ) {
			permission = BasePermission.READ;
		} else if (level == LEVEL_GRANT_WRITE) {
			permission = BasePermission.WRITE;
		} else if (level == LEVEL_GRANT_ADMIN) {
			permission = BasePermission.ADMINISTRATION;
		} else {
			throw new IllegalArgumentException("Unsupported LEVEL_");
		}
		
		// Attempt to retrieve the existing ACL, creating an ACL if it doesn't already exist for this ObjectIdentity
		MutableAcl acl = null;
		try {
			acl = (MutableAcl) aclService.readAclById(identity);
		} catch (NotFoundException nfe) {
			acl = aclService.createAcl(identity);
			Assert.notNull(acl, "Acl could not be retrieved or created");
		}
		
		// Now we have an ACL, add another ACE to it
		if (level == LEVEL_NEGATE_READ) {
			acl.insertAce(null, permission, sid, false); // not granting
		} else {
			acl.insertAce(null, permission, sid, true); // granting
		}
		
		// Finally, persist the modified ACL
		aclService.updateAcl(acl);
	}
	
}
