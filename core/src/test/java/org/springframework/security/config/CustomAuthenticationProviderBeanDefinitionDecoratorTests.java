package org.springframework.security.config;

import org.junit.Test;
import org.springframework.security.util.InMemoryXmlApplicationContext;


public class CustomAuthenticationProviderBeanDefinitionDecoratorTests {
    
    @Test
    public void decoratorParsesSuccessfully() {
        InMemoryXmlApplicationContext ctx = new InMemoryXmlApplicationContext(
                "<b:bean id='someBean' class='org.springframework.security.config.TestBusinessBeanImpl'>" +
                "   <intercept-methods>" +
                "       <protect method='org.springframework.security.config.TestBusinessBean.*' access='ROLE_A' />" +
                "   </intercept-methods>" +
                "</b:bean>" + HttpSecurityBeanDefinitionParserTests.AUTH_PROVIDER_XML
        );
        
        ctx.getBean("someBean");
    }
}
