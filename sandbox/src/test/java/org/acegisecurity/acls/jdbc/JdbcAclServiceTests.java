package org.acegisecurity.acls.jdbc;

import java.util.Iterator;
import java.util.Map;

import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.test.AbstractDependencyInjectionSpringContextTests;

public class JdbcAclServiceTests extends AbstractDependencyInjectionSpringContextTests {

	protected String[] getConfigLocations() {
		return new String[] {"classpath:org/acegisecurity/acls/jdbc/applicationContext-test.xml"};
	}
	
	private JdbcAclService jdbcAclService;
	
	public void testStub() {
		ObjectIdentity id1 = new ObjectIdentityImpl("sample.contact.Contact", new Long(1));
		ObjectIdentity id2 = new ObjectIdentityImpl("sample.contact.Contact", new Long(2));
		ObjectIdentity id3 = new ObjectIdentityImpl("sample.contact.Contact", new Long(3));
		ObjectIdentity id4 = new ObjectIdentityImpl("sample.contact.Contact", new Long(4));
		ObjectIdentity id5 = new ObjectIdentityImpl("sample.contact.Contact", new Long(5));
		ObjectIdentity id6 = new ObjectIdentityImpl("sample.contact.Contact", new Long(6));
		Map map = jdbcAclService.readAclsById(new ObjectIdentity[] {id1, id2, id3, id4, id5, id6});
		Iterator iterator = map.keySet().iterator();
		while (iterator.hasNext()) {
			ObjectIdentity identity = (ObjectIdentity) iterator.next();
			assertEquals(identity, ((Acl)map.get(identity)).getObjectIdentity());
			System.out.println(map.get(identity));
		}
	}

	public void setJdbcAclService(JdbcAclService jdbcAclService) {
		this.jdbcAclService = jdbcAclService;
	}


}
