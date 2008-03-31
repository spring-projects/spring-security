package org.springframework.security.config;

import org.junit.After;
import org.junit.Test;
import org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException;
import org.springframework.security.util.InMemoryXmlApplicationContext;

/**
 * Tests which make sure invalid configurations are rejected by the namespace. In particular invalid top-level 
 * elements. These are likely to fail after the namespace has been updated using trang, but the spring-security.xsl
 * transform has not been applied. 
 * 
 * @author Luke Taylor
 * @version $Id$
 */
public class InvalidConfigurationTests {
    private InMemoryXmlApplicationContext appContext;
    
    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }   
    
    // Parser should throw a SAXParseException
    @Test(expected=XmlBeanDefinitionStoreException.class)
    public void passwordEncoderCannotAppearAtTopLevel() {
        setContext("<password-encoder hash='md5'/>");
    }
    
    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
