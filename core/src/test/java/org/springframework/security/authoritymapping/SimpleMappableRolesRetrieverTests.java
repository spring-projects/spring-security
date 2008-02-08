package org.springframework.security.authoritymapping;

import java.util.Arrays;
import java.util.Collection;

import junit.framework.TestCase;

/**
 * 
 * @author TSARDD
 * @since 18-okt-2007
 */
public class SimpleMappableRolesRetrieverTests extends TestCase {

	public final void testGetSetMappableRoles() {
		String[] roles = new String[] { "Role1", "Role2" };
		SimpleMappableAttributesRetriever r = new SimpleMappableAttributesRetriever();
		r.setMappableRoles(roles);
		String[] result = r.getMappableAttributes();
		Collection resultColl = Arrays.asList(result);
		Collection rolesColl = Arrays.asList(roles);
		assertTrue("Role collections do not match; result: " + resultColl + ", expected: " + rolesColl, rolesColl.containsAll(resultColl)
				&& resultColl.containsAll(rolesColl));
	}

}
