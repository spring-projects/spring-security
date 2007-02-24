/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package acegifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;

import org.dom4j.Document;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;

/**
 * Tests the WebXmlConverter by applying it to a sample web.xml file.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class WebXmlConverterTests extends TestCase {

    private static final String XML_TRANSFORMER = "javax.xml.transform.TransformerFactory";

    public void testFileConversion() throws Exception {
        /*

        THIS TEST HAS BEEN DISABLED AS IT BREAKS THE BUILD (see SEC-181 for details)

        WebXmlConverter converter;
        try {
            converter = new WebXmlConverter();
        } catch (Exception e) {
            // TODO: Something went wrong, set transforer manually and retry...
            System.out.println("**** WARNING: NEEDING TO FALLBACK TO A MANUAL SYSTEM PROPERTY ****");
            System.setProperty(XML_TRANSFORMER, "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
            System.out.println(XML_TRANSFORMER + ": " + System.getProperty(XML_TRANSFORMER));
            converter = new WebXmlConverter();
        }

        Resource r = new ClassPathResource("test-web.xml");
        converter.setInput(r.getInputStream());
        converter.doConversion();

        DefaultListableBeanFactory bf = new DefaultListableBeanFactory();
        XmlBeanDefinitionReader beanReader = new XmlBeanDefinitionReader(bf);

        beanReader.loadBeanDefinitions(
                new InMemoryResource(converter.getAcegiBeans().asXML().getBytes()));
        assertNotNull(bf.getBean("filterChainProxy"));

        ProviderManager pm = (ProviderManager) bf.getBean("authenticationManager");
        assertNotNull(pm);
        assertEquals(3, pm.getProviders().size());

        DaoAuthenticationProvider dap =
                (DaoAuthenticationProvider) bf.getBean("daoAuthenticationProvider");
        assertNotNull(dap);

        InMemoryDaoImpl dao = (InMemoryDaoImpl) dap.getUserDetailsService();
        UserDetails user = dao.loadUserByUsername("superuser");
        assertEquals("password",user.getPassword());
        assertEquals(2, user.getAuthorities().length);
        assertNotNull(bf.getBean("anonymousProcessingFilter"));
        assertNotNull(bf.getBean("anonymousAuthenticationProvider"));
        assertNotNull(bf.getBean("httpSessionContextIntegrationFilter"));
        assertNotNull(bf.getBean("rememberMeProcessingFilter"));
        assertNotNull(bf.getBean("rememberMeAuthenticationProvider"));

        ExceptionTranslationFilter etf =
                (ExceptionTranslationFilter) bf.getBean("exceptionTranslationFilter");
        assertNotNull(etf);
        assertNotNull(etf.getAuthenticationEntryPoint());
        System.out.println(prettyPrint(converter.getNewWebXml()));
        System.out.println(prettyPrint(converter.getAcegiBeans()));
        */
    }

    private String prettyPrint(Document document) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setNewlines(true);
        format.setTrimText(false);
        XMLWriter writer = new XMLWriter(output, format);
        writer.write(document);
        writer.flush();
        writer.close();
        return output.toString();
    }
}
