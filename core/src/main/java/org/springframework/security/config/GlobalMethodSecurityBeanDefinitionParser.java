package org.springframework.security.config;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.aop.config.AopNamespaceUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
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
    public static final String JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.annotation.Jsr250MethodDefinitionSource";
    public static final String JSR_250_VOTER_CLASS = "org.springframework.security.annotation.Jsr250Voter";
    private static final String ATT_ACCESS = "access";
    private static final String ATT_EXPRESSION = "expression";
    private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";
    private static final String ATT_USE_JSR250 = "jsr250-annotations";
    private static final String ATT_USE_SECURED = "secured-annotations";

    private void validatePresent(String className, Element element, ParserContext parserContext) {
    	if (!ClassUtils.isPresent(className, parserContext.getReaderContext().getBeanClassLoader())) {
    		parserContext.getReaderContext().error("Cannot locate '" + className + "'", element);
    	}
    }

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        Object source = parserContext.extractSource(element);
        // The list of method metadata delegates
        ManagedList delegates = new ManagedList();
        
        boolean jsr250Enabled = registerAnnotationBasedMethodDefinitionSources(element, parserContext, delegates);
        
        MapBasedMethodDefinitionSource mapBasedMethodDefinitionSource = new MapBasedMethodDefinitionSource();
        delegates.add(mapBasedMethodDefinitionSource);
        
        // Now create a Map<String, ConfigAttribute> for each <protect-pointcut> sub-element        
        Map pointcutMap = parseProtectPointcuts(parserContext, 
                DomUtils.getChildElementsByTagName(element, Elements.PROTECT_POINTCUT));
        
        if (pointcutMap.size() > 0) {
            registerProtectPointcutPostProcessor(parserContext, pointcutMap, mapBasedMethodDefinitionSource, source);
        }
        
        registerDelegatingMethodDefinitionSource(parserContext, delegates, source);
        
        // Register the applicable AccessDecisionManager, handling the special JSR 250 voter if being used
        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            ConfigUtils.registerDefaultAccessManagerIfNecessary(parserContext);

            if (jsr250Enabled) {
                ConfigUtils.addVoter(new RootBeanDefinition(JSR_250_VOTER_CLASS, null, null), parserContext);                
            }

            accessManagerId = BeanIds.ACCESS_MANAGER;
        }
        
        registerMethodSecurityInterceptor(parserContext, accessManagerId, source);
        
        registerAdvisor(parserContext, source);

        AopNamespaceUtils.registerAutoProxyCreatorIfNecessary(parserContext, element);
        
        return null;
    }
    
    /**
     * Checks whether JSR-250 and/or Secured annotations are enabled and adds the appropriate 
     * MethodDefinitionSource delegates if required. 
     */
    private boolean registerAnnotationBasedMethodDefinitionSources(Element element, ParserContext pc, ManagedList delegates) {
        boolean useJsr250 = "enabled".equals(element.getAttribute(ATT_USE_JSR250));
        boolean useSecured = "enabled".equals(element.getAttribute(ATT_USE_SECURED));
        
        // Check the required classes are present
        if (useSecured) {
            validatePresent(SECURED_METHOD_DEFINITION_SOURCE_CLASS, element, pc);
            validatePresent(SECURED_DEPENDENCY_CLASS, element, pc);
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(SECURED_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());
        }

        if (useJsr250) {
            validatePresent(JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS, element, pc);
            validatePresent(JSR_250_VOTER_CLASS, element, pc);
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());           
        }
        
        return useJsr250;
    }
    
    private void registerDelegatingMethodDefinitionSource(ParserContext parserContext, ManagedList delegates, Object source) {
        if (parserContext.getRegistry().containsBeanDefinition(BeanIds.DELEGATING_METHOD_DEFINITION_SOURCE)) {
            parserContext.getReaderContext().error("Duplicate <global-method-security> detected.", source);
        }
        RootBeanDefinition delegatingMethodDefinitionSource = new RootBeanDefinition(DelegatingMethodDefinitionSource.class);
        delegatingMethodDefinitionSource.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        delegatingMethodDefinitionSource.setSource(source);
        delegatingMethodDefinitionSource.getPropertyValues().addPropertyValue("methodDefinitionSources", delegates);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.DELEGATING_METHOD_DEFINITION_SOURCE, delegatingMethodDefinitionSource);        
    }
    
    private void registerProtectPointcutPostProcessor(ParserContext parserContext, Map pointcutMap,
            MapBasedMethodDefinitionSource mapBasedMethodDefinitionSource, Object source) {
        RootBeanDefinition ppbp = new RootBeanDefinition(ProtectPointcutPostProcessor.class);
        ppbp.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        ppbp.setSource(source);
        ppbp.getConstructorArgumentValues().addGenericArgumentValue(mapBasedMethodDefinitionSource);
        ppbp.getPropertyValues().addPropertyValue("pointcutMap", pointcutMap);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.PROTECT_POINTCUT_POST_PROCESSOR, ppbp);
    }

    private Map parseProtectPointcuts(ParserContext parserContext, List protectPointcutElts) {
        Map pointcutMap = new LinkedHashMap();

        for (Iterator i = protectPointcutElts.iterator(); i.hasNext();) {
            Element childElt = (Element) i.next();
            String accessConfig = childElt.getAttribute(ATT_ACCESS);
            String expression = childElt.getAttribute(ATT_EXPRESSION);

            if (!StringUtils.hasText(accessConfig)) {
                parserContext.getReaderContext().error("Access configuration required", parserContext.extractSource(childElt));
            }

            if (!StringUtils.hasText(expression)) {
                parserContext.getReaderContext().error("Pointcut expression required", parserContext.extractSource(childElt));
            }

            ConfigAttributeDefinition def = new ConfigAttributeDefinition(StringUtils.commaDelimitedListToStringArray(accessConfig));
            pointcutMap.put(expression, def);
        }

        return pointcutMap;
    }

    private void registerMethodSecurityInterceptor(ParserContext parserContext, String accessManagerId, Object source) {
        RootBeanDefinition interceptor = new RootBeanDefinition(MethodSecurityInterceptor.class);
        interceptor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        interceptor.setSource(source);
        
        interceptor.getPropertyValues().addPropertyValue("accessDecisionManager", new RuntimeBeanReference(accessManagerId));
        interceptor.getPropertyValues().addPropertyValue("authenticationManager", new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));
        interceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", new RuntimeBeanReference(BeanIds.DELEGATING_METHOD_DEFINITION_SOURCE));
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_SECURITY_INTERCEPTOR, interceptor);
        parserContext.registerComponent(new BeanComponentDefinition(interceptor, BeanIds.METHOD_SECURITY_INTERCEPTOR));
        
        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_SECURITY_INTERCEPTOR_POST_PROCESSOR,
        		new RootBeanDefinition(MethodSecurityInterceptorPostProcessor.class));
    }

    private void registerAdvisor(ParserContext parserContext, Object source) {
        RootBeanDefinition advisor = new RootBeanDefinition(MethodDefinitionSourceAdvisor.class);
        advisor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        advisor.setSource(source);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(BeanIds.METHOD_SECURITY_INTERCEPTOR);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(new RuntimeBeanReference(BeanIds.DELEGATING_METHOD_DEFINITION_SOURCE));

        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_DEFINITION_SOURCE_ADVISOR, advisor);        
    }    
}
