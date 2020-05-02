package org.springframework.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ApacheDsContainerConfig.class)
public class SpringLdapFalseAuthTest {


	@Test(expected = IllegalArgumentException.class)
	public void testInMemoryDirectoryServerInvalidLdifFile(){
		//TODO - get exception here in case of invalid root base
		try {
			new InMemoryDirectoryServer("dc=springframework,dc=org",
					"classpath:missing-file.ldif");
		} catch (LDAPException e) {
			throw new IllegalArgumentException(e);
		}
	}



}
