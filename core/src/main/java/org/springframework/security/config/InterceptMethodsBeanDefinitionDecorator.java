package org.springframework.security.config;

import org.springframework.aop.config.AbstractInterceptorDrivenBeanDefinitionDecorator;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.intercept.method.MethodDefinitionMap;
import org.springframework.security.ConfigAttributeEditor;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Node;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Iterator;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class InterceptMethodsBeanDefinitionDecorator extends AbstractInterceptorDrivenBeanDefinitionDecorator {
    protected BeanDefinition createInterceptorDefinition(Node node) {
        Element interceptMethodsElt = (Element)node;
        RootBeanDefinition interceptor = new RootBeanDefinition(MethodSecurityInterceptor.class);

        Element beanNode = (Element)interceptMethodsElt.getParentNode();
        // Get the class from the parent bean...
        String targetClassName = beanNode.getAttribute("class");
        Class targetClass;

        try {
            targetClass = Thread.currentThread().getContextClassLoader().loadClass(targetClassName);
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("Couldn't load class " + targetClassName, e);
        }

        // Parse the included methods
        List methods = DomUtils.getChildElementsByTagName(interceptMethodsElt, "protect");
        MethodDefinitionMap methodMap = new MethodDefinitionMap();
        ConfigAttributeEditor attributeEditor = new ConfigAttributeEditor();

        for (Iterator i = methods.iterator(); i.hasNext();) {
            Element protectmethodElt = (Element) i.next();
            String accessConfig = protectmethodElt.getAttribute("access");
            attributeEditor.setAsText(accessConfig);

// TODO: We want to use just the method names, but MethodDefinitionMap won't work that way.            
//            methodMap.addSecureMethod(targetClass, protectmethodElt.getAttribute("method"),
//                    (ConfigAttributeDefinition) attributeEditor.getValue());
            methodMap.addSecureMethod(protectmethodElt.getAttribute("method"), 
                    (ConfigAttributeDefinition) attributeEditor.getValue());
        }

        interceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", methodMap);

        interceptor.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);

        return interceptor;
    }
}
