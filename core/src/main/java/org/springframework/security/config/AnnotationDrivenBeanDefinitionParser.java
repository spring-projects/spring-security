package org.springframework.security.config;

import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.metadata.Attributes;
import org.springframework.security.intercept.method.MethodDefinitionAttributes;
import org.springframework.security.intercept.method.aopalliance.MethodDefinitionSourceAdvisor;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;
import org.w3c.dom.Element;

/**
 * Processes the top-level "annotation-driven" element.
 * 
 * @author Ben Alex
 * @version $Id$
 */
class AnnotationDrivenBeanDefinitionParser implements BeanDefinitionParser {

	public static final String SECURITY_ANNOTATION_ATTRIBUTES_CLASS = "org.springframework.security.annotation.SecurityAnnotationAttributes";
	
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        // Reflectively obtain the Annotation-based ObjectDefinitionSource.
    	// Reflection is used to avoid a compile-time dependency on SECURITY_ANNOTATION_ATTRIBUTES_CLASS, as this parser is in the Java 4 project whereas the dependency is in the Tiger project.
    	Assert.isTrue(ClassUtils.isPresent(SECURITY_ANNOTATION_ATTRIBUTES_CLASS), "Could not locate class '" + SECURITY_ANNOTATION_ATTRIBUTES_CLASS + "' - please ensure the spring-security-tiger-xxx.jar is in your classpath and you are running Java 5 or above.");
    	Class clazz = null;
    	try {
    		clazz = ClassUtils.forName(SECURITY_ANNOTATION_ATTRIBUTES_CLASS);
    	} catch (Exception ex) {
    		ReflectionUtils.handleReflectionException(ex);
    	}
    	
        RootBeanDefinition securityAnnotations = new RootBeanDefinition(clazz);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.SECURITY_ANNOTATION_ATTRIBUTES, securityAnnotations);

        RootBeanDefinition methodDefinitionAttributes = new RootBeanDefinition(MethodDefinitionAttributes.class);
        methodDefinitionAttributes.getPropertyValues().addPropertyValue("attributes", new RuntimeBeanReference(BeanIds.SECURITY_ANNOTATION_ATTRIBUTES));
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_DEFINITION_ATTRIBUTES, methodDefinitionAttributes);
        
    	MethodSecurityInterceptorUtils.registerPostProcessorIfNecessary(parserContext.getRegistry());
    	
        RootBeanDefinition interceptor = new RootBeanDefinition(MethodSecurityInterceptor.class);
        interceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", new RuntimeBeanReference(BeanIds.METHOD_DEFINITION_ATTRIBUTES));
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_SECURITY_INTERCEPTOR, interceptor);
        
        RootBeanDefinition advisor = new RootBeanDefinition(MethodDefinitionSourceAdvisor.class);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(interceptor);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_DEFINITION_SOURCE_ADVISOR, advisor);
        
        RootBeanDefinition daapc = new RootBeanDefinition(DefaultAdvisorAutoProxyCreator.class);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.DEFAULT_ADVISOR_AUTO_PROXY_CREATOR, daapc);
        
        
        return null;
    }
}
