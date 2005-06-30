package net.sf.acegisecurity.util;

import junit.framework.TestCase;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.AbstractResource;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.w3c.dom.Node;

import net.sf.acegisecurity.providers.ProviderManager;
import net.sf.acegisecurity.providers.dao.DaoAuthenticationProvider;
import net.sf.acegisecurity.providers.dao.memory.InMemoryDaoImpl;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.intercept.web.SecurityEnforcementFilter;

import net.sf.acegisecurity.intercept.web.FilterSecurityInterceptor;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;

/**
 * Tests the WebXmlToAcegiSecurityConverter by applying it to a sample web.xml file.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class WebXmlToAcegiSecurityConverterTests extends TestCase {

    public void testFileConversion() throws Exception {
        WebXmlToAcegiSecurityConverter t = new WebXmlToAcegiSecurityConverter();

        Resource r = new ClassPathResource("test-web.xml");
        t.setInput(r.getInputStream());
        t.doConversion();


        DefaultListableBeanFactory bf = new DefaultListableBeanFactory();
        XmlBeanDefinitionReader beanReader = new XmlBeanDefinitionReader(bf);

        int nBeans = beanReader.loadBeanDefinitions(new InMemoryResource(t.getAcegiBeansXml()));
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

    private static class InMemoryResource extends AbstractResource {
        ByteArrayInputStream in;

        public InMemoryResource(ByteArrayInputStream in) {
            this.in = in;
        }

        public InMemoryResource(String source) {
            in = new ByteArrayInputStream(source.getBytes());
        }

        public String getDescription() {
            return in.toString();
        }

        public InputStream getInputStream() throws IOException {
            return in;
        }
    }
}
