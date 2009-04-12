package org.springframework.security.authoritymapping;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.HashSet;

import junit.framework.TestCase;
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
