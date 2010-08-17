package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityNamespaceHandlerTests {
    @Test
    public void constructionSucceeds() {
        new SecurityNamespaceHandler();
    }

    @Test
    public void pre31SchemaAreNotSupported() throws Exception {
        try {
            new InMemoryXmlApplicationContext(
                    "<user-service id='us'>" +
                    "  <user name='bob' password='bobspassword' authorities='ROLE_A' />" +
                    "</user-service>", "3.0.3", null
            );
            fail("Expected BeanDefinitionParsingException");
        } catch (BeanDefinitionParsingException expected) {
            assertTrue(expected.getMessage().contains("You cannot use a spring-security-2.0.xsd or"));
        }
    }
}
