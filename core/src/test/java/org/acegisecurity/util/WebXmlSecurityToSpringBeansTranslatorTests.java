package net.sf.acegisecurity.util;

import junit.framework.TestCase;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.beans.factory.BeanFactory;

import net.sf.acegisecurity.providers.ProviderManager;
import net.sf.acegisecurity.providers.dao.DaoAuthenticationProvider;
import net.sf.acegisecurity.providers.dao.memory.InMemoryDaoImpl;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.intercept.web.SecurityEnforcementFilter;

import net.sf.acegisecurity.intercept.web.FilterSecurityInterceptor;

/**
 * Tests the WebXmlSecurityToSpringBeansTranslator by applying it
 * to a test sample web.xml file.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class WebXmlSecurityToSpringBeansTranslatorTests extends TestCase {

    public void testFileTranslation() throws Exception {
        WebXmlSecurityToSpringBeansTranslator t = new WebXmlSecurityToSpringBeansTranslator();

        Resource r = new ClassPathResource("test-web.xml");
        t.translate(r.getInputStream());

        BeanFactory bf = t.getBeanFactory();
        assertNotNull(bf.getBean("filterChainProxy"));

        ProviderManager pm = (ProviderManager) bf.getBean("authenticationManager");
        assertNotNull(pm);
        assertEquals(3, pm.getProviders().size());

        DaoAuthenticationProvider dap =
                (DaoAuthenticationProvider) bf.getBean("daoAuthenticationProvider");
        assertNotNull(dap);

        InMemoryDaoImpl dao = (InMemoryDaoImpl) dap.getAuthenticationDao();
        UserDetails user = dao.loadUserByUsername("superuser");
        assertEquals("password",user.getPassword());
        assertEquals(2, user.getAuthorities().length);
        assertNotNull(bf.getBean("anonymousProcessingFilter"));
        assertNotNull(bf.getBean("anonymousAuthenticationProvider"));
        assertNotNull(bf.getBean("httpSessionContextIntegrationFilter"));
        assertNotNull(bf.getBean("rememberMeProcessingFilter"));
        assertNotNull(bf.getBean("rememberMeAuthenticationProvider"));

        SecurityEnforcementFilter sef =
                (SecurityEnforcementFilter) bf.getBean("securityEnforcementFilter");
        assertNotNull(sef);
        assertNotNull(sef.getAuthenticationEntryPoint());
        FilterSecurityInterceptor fsi = sef.getFilterSecurityInterceptor();

    }
}
