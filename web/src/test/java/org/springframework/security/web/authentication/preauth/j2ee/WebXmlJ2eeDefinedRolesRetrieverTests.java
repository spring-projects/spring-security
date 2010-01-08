package org.springframework.security.web.authentication.preauth.j2ee;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

public class WebXmlJ2eeDefinedRolesRetrieverTests {

    @Test
    public void testRole1To4Roles() throws Exception {
        List<String> ROLE1TO4_EXPECTED_ROLES = Arrays.asList(new String[] { "Role1", "Role2", "Role3", "Role4" });
        final Resource webXml = new ClassPathResource("webxml/Role1-4.web.xml");
        WebXmlMappableAttributesRetriever rolesRetriever = new WebXmlMappableAttributesRetriever();

        rolesRetriever.setResourceLoader(new ResourceLoader() {
            public ClassLoader getClassLoader() {
                return Thread.currentThread().getContextClassLoader();
            }

            public Resource getResource(String location) {
                return webXml;
            }
        });

        rolesRetriever.afterPropertiesSet();
        Set<String> j2eeRoles = rolesRetriever.getMappableAttributes();
        assertNotNull(j2eeRoles);
        assertTrue("J2eeRoles expected size: " + ROLE1TO4_EXPECTED_ROLES.size() + ", actual size: " + j2eeRoles.size(),
                j2eeRoles.size() == ROLE1TO4_EXPECTED_ROLES.size());
        assertTrue("J2eeRoles expected contents (arbitrary order): " + ROLE1TO4_EXPECTED_ROLES + ", actual content: " + j2eeRoles,
                j2eeRoles.containsAll(ROLE1TO4_EXPECTED_ROLES));
    }

    @Test
    public void testGetZeroJ2eeRoles() throws Exception {
        final Resource webXml = new ClassPathResource("webxml/NoRoles.web.xml");
        WebXmlMappableAttributesRetriever rolesRetriever = new WebXmlMappableAttributesRetriever();
        rolesRetriever.setResourceLoader(new ResourceLoader() {
            public ClassLoader getClassLoader() {
                return Thread.currentThread().getContextClassLoader();
            }

            public Resource getResource(String location) {
                return webXml;
            }
        });
        rolesRetriever.afterPropertiesSet();
        Set<String> j2eeRoles = rolesRetriever.getMappableAttributes();
        assertEquals("J2eeRoles expected size: 0, actual size: " + j2eeRoles.size(), 0, j2eeRoles.size());
    }
}
