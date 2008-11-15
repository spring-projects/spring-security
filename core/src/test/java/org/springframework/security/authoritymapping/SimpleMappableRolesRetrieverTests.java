package org.springframework.security.authoritymapping;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

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
        r.setMappableAttributes(roles);
        Set<String> result = r.getMappableAttributes();
        Collection<String> rolesColl = Arrays.asList(roles);
        assertTrue("Role collections do not match; result: " + result + ", expected: " + rolesColl, rolesColl.containsAll(result)
                && result.containsAll(rolesColl));
    }

}
