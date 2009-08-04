package org.springframework.security.config.method;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;

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
    public void customAfterInvocationProviderIsSupportedIn20Schema() {
        appContext = new InMemoryXmlApplicationContext(
                "<b:bean id='aip' class='org.springframework.security.config.MockAfterInvocationProvider'>" +
                "    <custom-after-invocation-provider />" +
                "</b:bean>", "2.0.4", null);
    }
}
