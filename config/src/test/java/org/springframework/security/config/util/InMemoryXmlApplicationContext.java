package org.springframework.security.config.util;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.security.util.InMemoryResource;

/**
 * @author Luke Taylor
 */
public class InMemoryXmlApplicationContext extends AbstractXmlApplicationContext {
    private static final String BEANS_OPENING =
                    "<b:beans xmlns='http://www.springframework.org/schema/security'\n" +
                    "    xmlns:b='http://www.springframework.org/schema/beans'\n" +
                    "    xmlns:aop='http://www.springframework.org/schema/aop'\n" +
                    "    xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\n" +
                    "    xsi:schemaLocation='http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-2.5.xsd\n" +
                    "http://www.springframework.org/schema/aop http://www.springframework.org/schema/aop/spring-aop-2.5.xsd\n" +
                    "http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security-";
    private static final String BEANS_CLOSE = "</b:beans>\n";

    Resource inMemoryXml;

    public InMemoryXmlApplicationContext(String xml) {
        this(xml, "3.1", null);
    }

    public InMemoryXmlApplicationContext(String xml, ApplicationContext parent) {
        this(xml, "3.1", parent);
    }

    public InMemoryXmlApplicationContext(String xml, String secVersion, ApplicationContext parent) {
        String fullXml = BEANS_OPENING + secVersion + ".xsd'>\n" + xml + BEANS_CLOSE;
        inMemoryXml = new InMemoryResource(fullXml);
        setAllowBeanDefinitionOverriding(false);
        setParent(parent);
        refresh();
    }

    protected Resource[] getConfigResources() {
        return new Resource[] {inMemoryXml};
    }
}
