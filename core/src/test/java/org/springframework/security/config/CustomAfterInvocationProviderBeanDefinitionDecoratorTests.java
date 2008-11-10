package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.afterinvocation.AfterInvocationProviderManager;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.util.InMemoryXmlApplicationContext;

public class CustomAfterInvocationProviderBeanDefinitionDecoratorTests {
    private AbstractXmlApplicationContext appContext;

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
            appContext = null;
        }
    }

    @Test
    public void customAfterInvocationProviderIsAddedToInterceptor() {
        setContext(
                "<global-method-security />" +
                "<b:bean id='aip' class='org.springframework.security.config.MockAfterInvocationProvider'>" +
                "    <custom-after-invocation-provider />" +
                "</b:bean>" +
                ConfigTestUtils.AUTH_PROVIDER_XML
        );

        MethodSecurityInterceptor msi = (MethodSecurityInterceptor) appContext.getBean(GlobalMethodSecurityBeanDefinitionParser.SECURITY_INTERCEPTOR_ID);
        AfterInvocationProviderManager apm = (AfterInvocationProviderManager) msi.getAfterInvocationManager();
        assertNotNull(apm);
        assertEquals(1, apm.getProviders().size());
        assertTrue(apm.getProviders().get(0) instanceof MockAfterInvocationProvider);
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
