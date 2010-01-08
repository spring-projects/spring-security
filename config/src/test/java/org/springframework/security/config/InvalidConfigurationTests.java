package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException;
import org.springframework.security.config.authentication.AuthenticationManagerFactoryBean;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;

/**
 * Tests which make sure invalid configurations are rejected by the namespace. In particular invalid top-level
 * elements. These are likely to fail after the namespace has been updated using trang, but the spring-security.xsl
 * transform has not been applied.
 *
 * @author Luke Taylor
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

    @Test(expected=XmlBeanDefinitionStoreException.class)
    public void authenticationProviderCannotAppearAtTopLevel() {
        setContext("<authentication-provider ref='blah'/>");
    }

    @Test
    public void missingAuthenticationManagerGivesSensibleErrorMessage() {
        try {
            setContext("<http auto-config='true' />");
        } catch (BeanCreationException e) {
            assertTrue(e.getCause().getCause() instanceof NoSuchBeanDefinitionException);
            NoSuchBeanDefinitionException nsbe = (NoSuchBeanDefinitionException) e.getCause().getCause();
            assertEquals(BeanIds.AUTHENTICATION_MANAGER, nsbe.getBeanName());
            assertTrue(nsbe.getMessage().endsWith(AuthenticationManagerFactoryBean.MISSING_BEAN_ERROR_MESSAGE));
        }
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
