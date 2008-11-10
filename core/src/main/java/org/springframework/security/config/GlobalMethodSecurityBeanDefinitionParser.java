package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.config.AopNamespaceUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.SecurityConfig;
import org.springframework.security.expression.DefaultSecurityExpressionHandler;
import org.springframework.security.expression.support.MethodExpressionAfterInvocationProvider;
import org.springframework.security.expression.support.MethodExpressionVoter;
import org.springframework.security.intercept.method.DelegatingMethodDefinitionSource;
import org.springframework.security.intercept.method.MapBasedMethodDefinitionSource;
import org.springframework.security.intercept.method.ProtectPointcutPostProcessor;
import org.springframework.security.intercept.method.aopalliance.MethodDefinitionSourceAdvisor;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.vote.AffirmativeBased;
import org.springframework.security.vote.AuthenticatedVoter;
import org.springframework.security.vote.RoleVoter;
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

    private final Log logger = LogFactory.getLog(getClass());

    static final String SECURED_DEPENDENCY_CLASS = "org.springframework.security.annotation.Secured";
    static final String SECURED_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.annotation.SecuredMethodDefinitionSource";
    static final String EXPRESSION_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.expression.support.ExpressionAnnotationMethodDefinitionSource";
    static final String JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.annotation.Jsr250MethodDefinitionSource";
    static final String JSR_250_VOTER_CLASS = "org.springframework.security.annotation.Jsr250Voter";

    /*
     * Internal Bean IDs which are only used within this class
     */
    static final String SECURITY_INTERCEPTOR_ID = "_globalMethodSecurityInterceptor";
    static final String INTERCEPTOR_POST_PROCESSOR_ID = "_globalMethodSecurityInterceptorPostProcessor";
    static final String ACCESS_MANAGER_ID = "_globalMethodSecurityAccessManager";
    static final String DELEGATING_METHOD_DEFINITION_SOURCE_ID = "_delegatingMethodDefinitionSource";
    static final String EXPRESSION_HANDLER_ID = "_expressionHandler";

    private static final String ATT_ACCESS = "access";
    private static final String ATT_EXPRESSION = "expression";
    private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";
    private static final String ATT_USE_JSR250 = "jsr250-annotations";
    private static final String ATT_USE_SECURED = "secured-annotations";
    private static final String ATT_USE_EXPRESSIONS = "expression-annotations";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        Object source = parserContext.extractSource(element);
        // The list of method metadata delegates
        ManagedList delegates = new ManagedList();

        boolean jsr250Enabled = "enabled".equals(element.getAttribute(ATT_USE_JSR250));
        boolean useSecured = "enabled".equals(element.getAttribute(ATT_USE_SECURED));
        boolean expressionsEnabled = "enabled".equals(element.getAttribute(ATT_USE_EXPRESSIONS));

        if (expressionsEnabled) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(EXPRESSION_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());
        }

        if (useSecured) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(SECURED_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());
        }

        if (jsr250Enabled) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());
        }

        MapBasedMethodDefinitionSource mapBasedMethodDefinitionSource = new MapBasedMethodDefinitionSource();
        delegates.add(mapBasedMethodDefinitionSource);

        // Now create a Map<String, ConfigAttribute> for each <protect-pointcut> sub-element
        Map pointcutMap = parseProtectPointcuts(parserContext,
                DomUtils.getChildElementsByTagName(element, Elements.PROTECT_POINTCUT));

        if (pointcutMap.size() > 0) {
            registerProtectPointcutPostProcessor(parserContext, pointcutMap, mapBasedMethodDefinitionSource, source);
        }

        registerDelegatingMethodDefinitionSource(parserContext, delegates, source);

        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            registerAccessManager(element, parserContext, jsr250Enabled, expressionsEnabled);
            accessManagerId = ACCESS_MANAGER_ID;
        }

        registerMethodSecurityInterceptor(parserContext, accessManagerId, source);

        registerAdvisor(parserContext, source);

        AopNamespaceUtils.registerAutoProxyCreatorIfNecessary(parserContext, element);

        return null;
    }

    /**
     * Register the default AccessDecisionManager. Adds the special JSR 250 voter jsr-250 is enabled and an
     * expression voter if expression-based access control is enabled. If expressions are in use, a after-invocation
     * provider will also be registered to handle post-invocation filtering and authorization expression annotations.
     */
    private void registerAccessManager(Element element, ParserContext pc, boolean jsr250Enabled, boolean expressionsEnabled) {
        Element permissionEvaluatorElt = DomUtils.getChildElementByTagName(element, Elements.PERMISSON_EVALUATOR);
        BeanDefinitionBuilder accessMgrBuilder = BeanDefinitionBuilder.rootBeanDefinition(AffirmativeBased.class);
        ManagedList voters = new ManagedList(4);

        if (expressionsEnabled) {
            BeanDefinitionBuilder expressionHandler = BeanDefinitionBuilder.rootBeanDefinition(DefaultSecurityExpressionHandler.class);
            BeanDefinitionBuilder expressionVoter = BeanDefinitionBuilder.rootBeanDefinition(MethodExpressionVoter.class);
            BeanDefinitionBuilder afterInvocationProvider = BeanDefinitionBuilder.rootBeanDefinition(MethodExpressionAfterInvocationProvider.class);

            if (permissionEvaluatorElt != null) {
                String ref = permissionEvaluatorElt.getAttribute("ref");
                logger.info("Using bean '" + ref + "' as PermissionEvaluator implementation");
                expressionHandler.addPropertyReference("permissionEvaluator", ref);
            } else {
                logger.warn("Expressions were enabled but no PermissionEvaluator was configured. " +
                        "All hasPermision() expressions will evaluate to false.");
            }

            pc.getRegistry().registerBeanDefinition(EXPRESSION_HANDLER_ID, expressionHandler.getBeanDefinition());

            expressionVoter.addPropertyReference("expressionHandler", EXPRESSION_HANDLER_ID);
            afterInvocationProvider.addPropertyReference("expressionHandler", EXPRESSION_HANDLER_ID);
            ConfigUtils.getRegisteredAfterInvocationProviders(pc).add(afterInvocationProvider.getBeanDefinition());
            voters.add(expressionVoter.getBeanDefinition());
        }

        voters.add(new RootBeanDefinition(RoleVoter.class));
        voters.add(new RootBeanDefinition(AuthenticatedVoter.class));

        if (jsr250Enabled) {
            voters.add(new RootBeanDefinition(JSR_250_VOTER_CLASS, null, null));
        }

        accessMgrBuilder.addPropertyValue("decisionVoters", voters);

        pc.getRegistry().registerBeanDefinition(ACCESS_MANAGER_ID, accessMgrBuilder.getBeanDefinition());
    }

    private void registerDelegatingMethodDefinitionSource(ParserContext parserContext, ManagedList delegates, Object source) {
        if (parserContext.getRegistry().containsBeanDefinition(DELEGATING_METHOD_DEFINITION_SOURCE_ID)) {
            parserContext.getReaderContext().error("Duplicate <global-method-security> detected.", source);
        }
        RootBeanDefinition delegatingMethodDefinitionSource = new RootBeanDefinition(DelegatingMethodDefinitionSource.class);
        delegatingMethodDefinitionSource.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        delegatingMethodDefinitionSource.setSource(source);
        delegatingMethodDefinitionSource.getPropertyValues().addPropertyValue("methodDefinitionSources", delegates);
        parserContext.getRegistry().registerBeanDefinition(DELEGATING_METHOD_DEFINITION_SOURCE_ID, delegatingMethodDefinitionSource);
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

            String[] attributeTokens = StringUtils.commaDelimitedListToStringArray(accessConfig);
            List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>(attributeTokens.length);

            for(String token : attributeTokens) {
                attributes.add(new SecurityConfig(token));
            }

            pointcutMap.put(expression, attributes);
        }

        return pointcutMap;
    }

    private void registerMethodSecurityInterceptor(ParserContext parserContext, String accessManagerId, Object source) {
        RootBeanDefinition interceptor = new RootBeanDefinition(MethodSecurityInterceptor.class);
        interceptor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        interceptor.setSource(source);

        interceptor.getPropertyValues().addPropertyValue("accessDecisionManager", new RuntimeBeanReference(accessManagerId));
        interceptor.getPropertyValues().addPropertyValue("authenticationManager", new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));
        interceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", new RuntimeBeanReference(DELEGATING_METHOD_DEFINITION_SOURCE_ID));
        parserContext.getRegistry().registerBeanDefinition(SECURITY_INTERCEPTOR_ID, interceptor);
        parserContext.registerComponent(new BeanComponentDefinition(interceptor, SECURITY_INTERCEPTOR_ID));

        parserContext.getRegistry().registerBeanDefinition(INTERCEPTOR_POST_PROCESSOR_ID,
                new RootBeanDefinition(MethodSecurityInterceptorPostProcessor.class));
    }

    private void registerAdvisor(ParserContext parserContext, Object source) {
        RootBeanDefinition advisor = new RootBeanDefinition(MethodDefinitionSourceAdvisor.class);
        advisor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        advisor.setSource(source);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(SECURITY_INTERCEPTOR_ID);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(new RuntimeBeanReference(DELEGATING_METHOD_DEFINITION_SOURCE_ID));

        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_DEFINITION_SOURCE_ADVISOR, advisor);
    }
}
