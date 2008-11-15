package org.springframework.security.ui.preauth.j2ee;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;

public class WebXmlJ2eeDefinedRolesRetrieverTests extends TestCase {

    public final void testRole1To4Roles() throws Exception {
        final List<String> ROLE1TO4_EXPECTED_ROLES = Arrays.asList(new String[] { "Role1", "Role2", "Role3", "Role4" });
        InputStream role1to4InputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("webxml/Role1-4.web.xml");
        WebXmlMappableAttributesRetriever rolesRetriever = new WebXmlMappableAttributesRetriever();
        rolesRetriever.setWebXmlInputStream(role1to4InputStream);
        rolesRetriever.afterPropertiesSet();
        Set<String> j2eeRoles = rolesRetriever.getMappableAttributes();
        assertNotNull(j2eeRoles);
        assertTrue("J2eeRoles expected size: " + ROLE1TO4_EXPECTED_ROLES.size() + ", actual size: " + j2eeRoles.size(),
                j2eeRoles.size() == ROLE1TO4_EXPECTED_ROLES.size());
        assertTrue("J2eeRoles expected contents (arbitrary order): " + ROLE1TO4_EXPECTED_ROLES + ", actual content: " + j2eeRoles,
                j2eeRoles.containsAll(ROLE1TO4_EXPECTED_ROLES));
    }

    public final void testGetZeroJ2eeRoles() throws Exception {
        InputStream noRolesInputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("webxml/NoRoles.web.xml");
        WebXmlMappableAttributesRetriever rolesRetriever = new WebXmlMappableAttributesRetriever();
        rolesRetriever.setWebXmlInputStream(noRolesInputStream);
        rolesRetriever.afterPropertiesSet();
        Set<String> j2eeRoles = rolesRetriever.getMappableAttributes();
        assertEquals("J2eeRoles expected size: 0, actual size: " + j2eeRoles.size(), 0, j2eeRoles.size());
    }
}
