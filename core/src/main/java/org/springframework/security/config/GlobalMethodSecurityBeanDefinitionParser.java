package org.springframework.security.config;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.aop.config.AopNamespaceUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.intercept.method.DelegatingMethodDefinitionSource;
import org.springframework.security.intercept.method.MapBasedMethodDefinitionSource;
import org.springframework.security.intercept.method.ProtectPointcutPostProcessor;
import org.springframework.security.intercept.method.aopalliance.MethodDefinitionSourceAdvisor;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Processes the top-level "global-method-security" element.
 * 
 * @author Ben Alex
 * @version $Id$
 */
class GlobalMethodSecurityBeanDefinitionParser implements BeanDefinitionParser {
    public static final String SECURED_DEPENDENCY_CLASS = "org.springframework.security.annotation.Secured";
    public static final String SECURED_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.annotation.SecuredMethodDefinitionSource";
    public static final String JSR_250_DEPENDENCY_CLASS = "javax.annotation.security.DenyAll";
    public static final String JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.annotation.Jsr250MethodDefinitionSource";
    public static final String JSR_250_VOTER_CLASS = "org.springframework.security.annotation.Jsr250Voter";
    private static final String ATT_ACCESS = "access";
    private static final String ATT_EXPRESSION = "expression";
    private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";
    private static final String ATT_USE_JSR250 = "jsr250-annotations";
    private static final String ATT_USE_SECURED = "secured-annotations";

    private void validatePresent(String className) {
    	Assert.isTrue(ClassUtils.isPresent(className), "Cannot locate '" + className + "'");
    }
    
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        boolean useJsr250 = "enabled".equals(element.getAttribute(ATT_USE_JSR250));
        boolean useSecured = "enabled".equals(element.getAttribute(ATT_USE_SECURED));

        // Check the required classes are present
        if (useSecured) {
        	validatePresent(SECURED_METHOD_DEFINITION_SOURCE_CLASS);
        	validatePresent(SECURED_DEPENDENCY_CLASS);
        }

        if (useJsr250) {
        	validatePresent(JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS);
        	validatePresent(JSR_250_VOTER_CLASS);
        	validatePresent(JSR_250_DEPENDENCY_CLASS);
        }
        
        // Now create a Map<String, ConfigAttribute> for each <protect-pointcut> sub-element
        Map pointcutMap = new LinkedHashMap();
        List protect = DomUtils.getChildElementsByTagName(element, Elements.PROTECT_POINTCUT);

        for (Iterator i = protect.iterator(); i.hasNext();) {
            Element childElt = (Element) i.next();
            String accessConfig = childElt.getAttribute(ATT_ACCESS);
            String expression = childElt.getAttribute(ATT_EXPRESSION);
            Assert.hasText(accessConfig, "Access configuration required for '" + childElt + "'");
            Assert.hasText(expression, "Expression required for '" + childElt + "'");
            
            ConfigAttributeDefinition def = new ConfigAttributeDefinition(StringUtils.commaDelimitedListToStringArray(accessConfig));
            pointcutMap.put(expression, def);
        }

        MapBasedMethodDefinitionSource mapBasedMethodDefinitionSource = new MapBasedMethodDefinitionSource();
        
        // Now create and populate our ProtectPointcutBeanPostProcessor, if needed
        if (pointcutMap.size() > 0) {
            RootBeanDefinition ppbp = new RootBeanDefinition(ProtectPointcutPostProcessor.class);
            ppbp.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            ppbp.getConstructorArgumentValues().addGenericArgumentValue(mapBasedMethodDefinitionSource);
            ppbp.getPropertyValues().addPropertyValue("pointcutMap", pointcutMap);
            parserContext.getRegistry().registerBeanDefinition(BeanIds.PROTECT_POINTCUT_POST_PROCESSOR, ppbp);
        }
        
        // Create our list of method metadata delegates
        ManagedList delegates = new ManagedList();
        delegates.add(mapBasedMethodDefinitionSource);
        
        if (useSecured) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(SECURED_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());
        }
        
        if (useJsr250) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());            
        }
        
    	// Register our DelegatingMethodDefinitionSource
        RootBeanDefinition delegatingMethodDefinitionSource = new RootBeanDefinition(DelegatingMethodDefinitionSource.class);
        delegatingMethodDefinitionSource.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        delegatingMethodDefinitionSource.getPropertyValues().addPropertyValue("methodDefinitionSources", delegates);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.DELEGATING_METHOD_DEFINITION_SOURCE, delegatingMethodDefinitionSource);

        // Register the applicable AccessDecisionManager, handling the special JSR 250 voter if being used
        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            ConfigUtils.registerDefaultAccessManagerIfNecessary(parserContext);

            if (useJsr250) {
                ConfigUtils.addVoter(new RootBeanDefinition(JSR_250_VOTER_CLASS, null, null), parserContext);                
            }

            accessManagerId = BeanIds.ACCESS_MANAGER;
        }

        // MethodSecurityInterceptor
        RootBeanDefinition interceptor = new RootBeanDefinition(MethodSecurityInterceptor.class);
        interceptor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

        interceptor.getPropertyValues().addPropertyValue("accessDecisionManager", new RuntimeBeanReference(accessManagerId));
        interceptor.getPropertyValues().addPropertyValue("authenticationManager", new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));
        interceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", new RuntimeBeanReference(BeanIds.DELEGATING_METHOD_DEFINITION_SOURCE));
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_SECURITY_INTERCEPTOR, interceptor);

        // MethodDefinitionSourceAdvisor
        RootBeanDefinition advisor = new RootBeanDefinition(MethodDefinitionSourceAdvisor.class);
        advisor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(interceptor);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_DEFINITION_SOURCE_ADVISOR, advisor);

        AopNamespaceUtils.registerAutoProxyCreatorIfNecessary(parserContext, element);

        return null;
    }
}
