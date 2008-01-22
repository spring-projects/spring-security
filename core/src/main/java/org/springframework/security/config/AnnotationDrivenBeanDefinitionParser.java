package org.springframework.security.config;

import org.springframework.aop.config.AopNamespaceUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.intercept.method.MethodDefinitionAttributes;
import org.springframework.security.intercept.method.aopalliance.MethodDefinitionSourceAdvisor;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * Processes the top-level "annotation-driven" element.
 *
 * @author Ben Alex
 * @version $Id$
 */
class AnnotationDrivenBeanDefinitionParser implements BeanDefinitionParser {
    public static final String SECURITY_ANNOTATION_ATTRIBUTES_CLASS = "org.springframework.security.annotation.SecurityAnnotationAttributes";
    public static final String JSR_250_SECURITY_ANNOTATION_ATTRIBUTES_CLASS = "org.springframework.security.annotation.Jsr250SecurityAnnotationAttributes";
    private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";
    private static final String ATT_USE_JSR250 = "jsr250";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        String className = "true".equals(element.getAttribute(ATT_USE_JSR250)) ?
                JSR_250_SECURITY_ANNOTATION_ATTRIBUTES_CLASS : SECURITY_ANNOTATION_ATTRIBUTES_CLASS;

        // Reflectively obtain the Annotation-based ObjectDefinitionSource.
    	// Reflection is used to avoid a compile-time dependency on SECURITY_ANNOTATION_ATTRIBUTES_CLASS, as this parser is in the Java 4 project whereas the dependency is in the Tiger project.
    	Assert.isTrue(ClassUtils.isPresent(className), "Could not locate class '" + className + "' - please ensure the spring-security-tiger-xxx.jar is in your classpath and you are running Java 5 or above.");
    	Class clazz = null;

        try {
    		clazz = ClassUtils.forName(className);
    	} catch (Exception ex) {
    		ReflectionUtils.handleReflectionException(ex);
    	}

        RootBeanDefinition securityAnnotations = new RootBeanDefinition(clazz);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.SECURITY_ANNOTATION_ATTRIBUTES, securityAnnotations);

        RootBeanDefinition methodDefinitionAttributes = new RootBeanDefinition(MethodDefinitionAttributes.class);
        methodDefinitionAttributes.getPropertyValues().addPropertyValue("attributes", new RuntimeBeanReference(BeanIds.SECURITY_ANNOTATION_ATTRIBUTES));
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_DEFINITION_ATTRIBUTES, methodDefinitionAttributes);

        RootBeanDefinition interceptor = new RootBeanDefinition(MethodSecurityInterceptor.class);

        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            ConfigUtils.registerDefaultAccessManagerIfNecessary(parserContext);
            accessManagerId = BeanIds.ACCESS_MANAGER;
        }

        interceptor.getPropertyValues().addPropertyValue("accessDecisionManager",
                new RuntimeBeanReference(accessManagerId));

        interceptor.getPropertyValues().addPropertyValue("authenticationManager",
                new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));

        interceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", new RuntimeBeanReference(BeanIds.METHOD_DEFINITION_ATTRIBUTES));
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_SECURITY_INTERCEPTOR, interceptor);

        RootBeanDefinition advisor = new RootBeanDefinition(MethodDefinitionSourceAdvisor.class);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(interceptor);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_DEFINITION_SOURCE_ADVISOR, advisor);

        AopNamespaceUtils.registerAutoProxyCreatorIfNecessary(parserContext, element);

        return null;
    }
}
