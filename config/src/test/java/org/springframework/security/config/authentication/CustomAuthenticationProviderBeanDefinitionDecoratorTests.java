package org.springframework.security.config.authentication;

import org.junit.Test;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;


public class CustomAuthenticationProviderBeanDefinitionDecoratorTests {

    @Test
    public void decoratedProviderParsesSuccessfullyWith20Namespace() {
        new InMemoryXmlApplicationContext(
                "<b:bean class='org.springframework.security.authentication.dao.DaoAuthenticationProvider'>" +
                "  <custom-authentication-provider />" +
                "  <b:property name='userDetailsService' ref='us'/>" +
                "</b:bean>" +
                "<user-service id='us'>" +
                " <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
                "</user-service>", "2.0.4", null);
    }
}
