package org.springframework.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ApacheDsContainerConfig.class)
public class SpringLdapFalseAuthTest {

	@Test
	public void testApacheDSContainerInvalidLdifFile(){

		//TODO - get exception here in case of invalid root base
		new ApacheDSContainer("dc=springframework,dc=org",
				"classpath:missing-file.ldif");
	}

	@Test(expected = LDAPException.class)
	public void testInMemoryDirectoryServerInvalidLdifFile(){
		//TODO - get exception here in case of invalid root base
		try {
			new InMemoryDirectoryServer("dc=springframework,dc=org",
					"classpath:missing-file.ldif");
		} catch (LDAPException e) {

		}
	}



}
