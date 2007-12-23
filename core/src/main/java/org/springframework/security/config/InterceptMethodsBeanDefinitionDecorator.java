package org.springframework.security.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.config.AbstractInterceptorDrivenBeanDefinitionDecorator;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.ConfigAttributeEditor;
import org.springframework.security.intercept.method.MethodDefinitionMap;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.util.xml.DomUtils;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Iterator;
import java.util.List;

/**
 * @author Luke Taylor
 * @author Ben Alex
 *
 * @version $Id$
 */
public class InterceptMethodsBeanDefinitionDecorator implements BeanDefinitionDecorator {
    private BeanDefinitionDecorator delegate = new InternalInterceptMethodsBeanDefinitionDecorator();

    public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder definition, ParserContext parserContext) {
        ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        ConfigUtils.registerDefaultAccessManagerIfNecessary(parserContext);

        return delegate.decorate(node, definition, parserContext);
    }
}

/**
 * This is the real class which does the work. We need acccess to the ParserContext in order to do bean
 * registration.
 */
class InternalInterceptMethodsBeanDefinitionDecorator extends AbstractInterceptorDrivenBeanDefinitionDecorator {
    static final String ATT_CLASS = "class";
	static final String ATT_METHOD = "method";
	static final String ATT_ACCESS = "access";
    private static final String ATT_ACCESS_MGR = "access-decision-manager";

    private Log logger = LogFactory.getLog(getClass());

    protected BeanDefinition createInterceptorDefinition(Node node) {
        Element interceptMethodsElt = (Element)node;
        RootBeanDefinition interceptor = new RootBeanDefinition(MethodSecurityInterceptor.class);

        String accessManagerId = interceptMethodsElt.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            accessManagerId = BeanIds.ACCESS_MANAGER;
        }

        interceptor.getPropertyValues().addPropertyValue("accessDecisionManager",
                new RuntimeBeanReference(accessManagerId));

        interceptor.getPropertyValues().addPropertyValue("authenticationManager",
                new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));

        Element beanNode = (Element)interceptMethodsElt.getParentNode();
        // Get the class from the parent bean...
        String targetClassName = beanNode.getAttribute(ATT_CLASS);
        Class targetClass;

        try {
            targetClass = Thread.currentThread().getContextClassLoader().loadClass(targetClassName);
        } catch (ClassNotFoundException e) {
            logger.error("Couldn't load class " + targetClassName);
            throw new SecurityConfigurationException("Couldn't load class " + targetClassName);
        }

        // Parse the included methods
        List methods = DomUtils.getChildElementsByTagName(interceptMethodsElt, Elements.PROTECT);
        MethodDefinitionMap methodMap = new MethodDefinitionMap();
        ConfigAttributeEditor attributeEditor = new ConfigAttributeEditor();

        for (Iterator i = methods.iterator(); i.hasNext();) {
            Element protectmethodElt = (Element) i.next();
            String accessConfig = protectmethodElt.getAttribute(ATT_ACCESS);
            attributeEditor.setAsText(accessConfig);

// TODO: We want to use just the method names, but MethodDefinitionMap won't work that way.
//            methodMap.addSecureMethod(targetClass, protectmethodElt.getAttribute("method"),
//                    (ConfigAttributeDefinition) attributeEditor.getValue());
            methodMap.addSecureMethod(protectmethodElt.getAttribute(ATT_METHOD),
                    (ConfigAttributeDefinition) attributeEditor.getValue());
        }

        interceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", methodMap);

        return interceptor;
    }
}
