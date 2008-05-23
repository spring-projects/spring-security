package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.util.InMemoryXmlApplicationContext;


public class CustomAuthenticationProviderBeanDefinitionDecoratorTests {
    
    @Test
    public void decoratedProviderParsesSuccessfully() {
        InMemoryXmlApplicationContext ctx = new InMemoryXmlApplicationContext(
                "<b:bean id='myProvider' class='org.springframework.security.providers.dao.DaoAuthenticationProvider'>" +
                "  <custom-authentication-provider />" +
                "  <b:property name='userDetailsService' ref='us'/>" +
                "</b:bean>" + 
                "<user-service id='us'>" +
                " <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
                " <user name='bill' password='billspassword' authorities='ROLE_A,ROLE_B,AUTH_OTHER' />" +
                "</user-service>"
                
        );
        
        Object myProvider = ctx.getBean("myProvider");
        
        ProviderManager authMgr = (ProviderManager) ctx.getBean(BeanIds.AUTHENTICATION_MANAGER);
        
        assertSame(myProvider, authMgr.getProviders().get(0));
    }
}
