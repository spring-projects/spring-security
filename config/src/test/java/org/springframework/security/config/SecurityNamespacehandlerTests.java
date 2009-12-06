package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class SecurityNamespacehandlerTests {

    @Test
    public void pre3SchemaAreNotSupported() throws Exception {
        try {
            new InMemoryXmlApplicationContext(
                    "<user-service id='us'>" +
                    "  <user name='bob' password='bobspassword' authorities='ROLE_A' />" +
                    "</user-service>", "2.0.4", null
            );
            fail("Expected BeanDefinitionParsingException");
        } catch (BeanDefinitionParsingException expected) {
            assertTrue(expected.getMessage().contains("You cannot use a spring-security-2.0.xsd schema"));
        }
    }
}
