package org.springframework.security.core.authoritymapping;

import java.util.Set;

import junit.framework.TestCase;

import org.springframework.security.core.authoritymapping.SimpleMappableAttributesRetriever;
import org.springframework.util.StringUtils;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class SimpleMappableRolesRetrieverTests extends TestCase {

    public final void testGetSetMappableRoles() {
        Set<String> roles = StringUtils.commaDelimitedListToSet("Role1,Role2");
        SimpleMappableAttributesRetriever r = new SimpleMappableAttributesRetriever();
        r.setMappableAttributes(roles);
        Set<String> result = r.getMappableAttributes();
        assertTrue("Role collections do not match; result: " + result + ", expected: " + roles, roles.containsAll(result)
                && result.containsAll(roles));
    }

}
