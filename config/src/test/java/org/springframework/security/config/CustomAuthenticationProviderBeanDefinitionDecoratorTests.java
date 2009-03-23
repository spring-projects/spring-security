package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.providers.ProviderManager;


public class CustomAuthenticationProviderBeanDefinitionDecoratorTests {

    @Test
    public void decoratedProviderParsesSuccessfully() {
        InMemoryXmlApplicationContext ctx = new InMemoryXmlApplicationContext(
                "<b:bean class='org.springframework.security.providers.dao.DaoAuthenticationProvider'>" +
                "  <custom-authentication-provider />" +
                "  <b:property name='userDetailsService' ref='us'/>" +
                "</b:bean>" + 
                "<user-service id='us'>" +
                " <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
                "</user-service>"
        );
        ProviderManager authMgr = (ProviderManager) ctx.getBean(BeanIds.AUTHENTICATION_MANAGER);
        assertEquals(1, authMgr.getProviders().size());        
    }
    
    
    @Test
    public void decoratedBeanAndRegisteredProviderAreTheSameObject() {
        InMemoryXmlApplicationContext ctx = new InMemoryXmlApplicationContext(
                "<b:bean id='myProvider' class='org.springframework.security.providers.dao.DaoAuthenticationProvider'>" +
                "  <custom-authentication-provider />" +
                "  <b:property name='userDetailsService' ref='us'/>" +
                "</b:bean>" + 
                "<user-service id='us'>" +
                " <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
                "</user-service>"
        );

        ProviderManager authMgr = (ProviderManager) ctx.getBean(BeanIds.AUTHENTICATION_MANAGER);
        assertEquals(1, authMgr.getProviders().size());
        assertSame(ctx.getBean("myProvider"), authMgr.getProviders().get(0));
    }
}
