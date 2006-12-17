import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.AclService;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import sample.dms.AbstractElement;
import sample.dms.Directory;



/**
 * Basic integration test for DMS sample when security has been added.
 * 
 * @author Ben Alex
 * @version $Id$
 *
 */
public class SecureDmsIntegrationTests extends DmsIntegrationTests {

	private AclService aclService;
	
	public void setAclService(AclService aclService) {
		this.aclService = aclService;
	}

	protected String[] getConfigLocations() {
		return new String[] {"classpath:applicationContext-dms-shared.xml", "classpath:applicationContext-dms-secure.xml"};
	}

	public void testBasePopulation() {
		assertEquals(9, jdbcTemplate.queryForInt("select count(id) from DIRECTORY"));
		assertEquals(90, jdbcTemplate.queryForInt("select count(id) from FILE"));
		assertEquals(4, jdbcTemplate.queryForInt("select count(id) from ACL_SID")); // 3 users + 1 role
		assertEquals(2, jdbcTemplate.queryForInt("select count(id) from ACL_CLASS")); // Directory and File
		assertEquals(100, jdbcTemplate.queryForInt("select count(id) from ACL_OBJECT_IDENTITY"));
		assertEquals(115, jdbcTemplate.queryForInt("select count(id) from ACL_ENTRY"));
	}
	/*
	public void testItOut() {
		SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("marissa", "password", new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_SUPERVISOR")}));
		
		
		AbstractElement[] elements = documentDao.findElements(Directory.ROOT_DIRECTORY);
		ObjectIdentity oid = new ObjectIdentityImpl(elements[0]);
		//ObjectIdentity oid = new ObjectIdentityImpl(Directory.class, new Long(3));
		Acl acl = aclService.readAclById(oid);
		System.out.println(acl);
		
	}*/
	
	public void testMarissaRetrieval() {
		process("marissa", "koala", true);
	}

	
	public void testScottRetrieval() {
		process("scott", "wombat", true);
	}
	
	public void testDianneRetrieval() {
		process("dianne", "emu", true);
	}
}
