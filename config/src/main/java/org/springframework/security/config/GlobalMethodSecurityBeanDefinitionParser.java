package org.springframework.security.config;

import java.util.ArrayList;
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
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.method.MethodExpressionAfterInvocationProvider;
import org.springframework.security.access.expression.method.MethodExpressionVoter;
import org.springframework.security.access.expression.support.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.intercept.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.intercept.method.ProtectPointcutPostProcessor;
import org.springframework.security.access.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.intercept.method.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Processes the top-level "global-method-security" element.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
class GlobalMethodSecurityBeanDefinitionParser implements BeanDefinitionParser {

    private final Log logger = LogFactory.getLog(getClass());

    static final String SECURED_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.access.annotation.SecuredMethodSecurityMetadataSource";
    static final String EXPRESSION_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.access.expression.method.ExpressionAnnotationMethodSecurityMetadataSource";
    static final String JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS = "org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource";
    static final String JSR_250_VOTER_CLASS = "org.springframework.security.access.annotation.Jsr250Voter";

    /*
     * Internal Bean IDs which are only used within this class
     */
    static final String SECURITY_INTERCEPTOR_ID = "_globalMethodSecurityInterceptor";
    static final String INTERCEPTOR_POST_PROCESSOR_ID = "_globalMethodSecurityInterceptorPostProcessor";
    static final String ACCESS_MANAGER_ID = "_globalMethodSecurityAccessManager";
    private static final String DELEGATING_METHOD_DEFINITION_SOURCE_ID = "_delegatingMethodSecurityMetadataSource";
    private static final String EXPRESSION_HANDLER_ID = "_methodExpressionHandler";

    private static final String ATT_ACCESS = "access";
    private static final String ATT_EXPRESSION = "expression";
    private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";
    private static final String ATT_USE_JSR250 = "jsr250-annotations";
    private static final String ATT_USE_SECURED = "secured-annotations";
    private static final String ATT_USE_EXPRESSIONS = "expression-annotations";

    @SuppressWarnings("unchecked")
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        Object source = parserContext.extractSource(element);
        // The list of method metadata delegates
        ManagedList delegates = new ManagedList();

        boolean jsr250Enabled = "enabled".equals(element.getAttribute(ATT_USE_JSR250));
        boolean useSecured = "enabled".equals(element.getAttribute(ATT_USE_SECURED));
        boolean expressionsEnabled = "enabled".equals(element.getAttribute(ATT_USE_EXPRESSIONS));
        BeanDefinition expressionVoter = null;

        // Now create a Map<String, ConfigAttribute> for each <protect-pointcut> sub-element
        Map<String, List<ConfigAttribute>> pointcutMap = parseProtectPointcuts(parserContext,
                DomUtils.getChildElementsByTagName(element, Elements.PROTECT_POINTCUT));

        if (pointcutMap.size() > 0) {
            // SEC-1016: Put the pointcut MDS first, but only add it if there are actually any pointcuts defined.
            MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource = new MapBasedMethodSecurityMetadataSource();
            delegates.add(mapBasedMethodSecurityMetadataSource);
            registerProtectPointcutPostProcessor(parserContext, pointcutMap, mapBasedMethodSecurityMetadataSource, source);
        }

        if (expressionsEnabled) {
            Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, Elements.EXPRESSION_HANDLER);
            String expressionHandlerRef = expressionHandlerElt == null ? null : expressionHandlerElt.getAttribute("ref");

            if (StringUtils.hasText(expressionHandlerRef)) {
                logger.info("Using bean '" + expressionHandlerRef + "' as method SecurityExpressionHandler implementation");
            } else {
                parserContext.getRegistry().registerBeanDefinition(EXPRESSION_HANDLER_ID, new RootBeanDefinition(DefaultMethodSecurityExpressionHandler.class));
                logger.warn("Expressions were enabled for method security but no SecurityExpressionHandler was configured. " +
                        "All hasPermision() expressions will evaluate to false.");
                expressionHandlerRef = EXPRESSION_HANDLER_ID;
            }
            BeanDefinitionBuilder expressionVoterBldr = BeanDefinitionBuilder.rootBeanDefinition(MethodExpressionVoter.class);
            BeanDefinitionBuilder afterInvocationProvider = BeanDefinitionBuilder.rootBeanDefinition(MethodExpressionAfterInvocationProvider.class);
            expressionVoterBldr.addPropertyReference("expressionHandler", expressionHandlerRef);
            expressionVoter = expressionVoterBldr.getBeanDefinition();
            // After-invocation provider to handle post-invocation filtering and authorization expression annotations.
            afterInvocationProvider.addPropertyReference("expressionHandler", expressionHandlerRef);
            ConfigUtils.getRegisteredAfterInvocationProviders(parserContext).add(afterInvocationProvider.getBeanDefinition());
            // Add the expression method definition source, which will obtain its parser from the registered expression
            // handler
            BeanDefinitionBuilder mds = BeanDefinitionBuilder.rootBeanDefinition(EXPRESSION_METHOD_DEFINITION_SOURCE_CLASS);
            mds.addConstructorArgReference(expressionHandlerRef);

            delegates.add(mds.getBeanDefinition());
        }

        if (useSecured) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(SECURED_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());
        }

        if (jsr250Enabled) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(JSR_250_SECURITY_METHOD_DEFINITION_SOURCE_CLASS).getBeanDefinition());
        }

        registerDelegatingMethodSecurityMetadataSource(parserContext, delegates, source);

        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            registerAccessManager(parserContext, jsr250Enabled, expressionVoter);
            accessManagerId = ACCESS_MANAGER_ID;
        }

        registerMethodSecurityInterceptor(parserContext, accessManagerId, source);

        registerAdvisor(parserContext, source);

        AopNamespaceUtils.registerAutoProxyCreatorIfNecessary(parserContext, element);

        return null;
    }

    /**
     * Register the default AccessDecisionManager. Adds the special JSR 250 voter jsr-250 is enabled and an
     * expression voter if expression-based access control is enabled.
     */
    @SuppressWarnings("unchecked")
    private void registerAccessManager(ParserContext pc, boolean jsr250Enabled, BeanDefinition expressionVoter) {

        BeanDefinitionBuilder accessMgrBuilder = BeanDefinitionBuilder.rootBeanDefinition(AffirmativeBased.class);
        ManagedList voters = new ManagedList(4);

        if (expressionVoter != null) {
            voters.add(expressionVoter);
        }
        voters.add(new RootBeanDefinition(RoleVoter.class));
        voters.add(new RootBeanDefinition(AuthenticatedVoter.class));

        if (jsr250Enabled) {
            voters.add(new RootBeanDefinition(JSR_250_VOTER_CLASS, null, null));
        }

        accessMgrBuilder.addPropertyValue("decisionVoters", voters);

        pc.getRegistry().registerBeanDefinition(ACCESS_MANAGER_ID, accessMgrBuilder.getBeanDefinition());
    }

    @SuppressWarnings("unchecked")
    private void registerDelegatingMethodSecurityMetadataSource(ParserContext parserContext, ManagedList delegates, Object source) {
        if (parserContext.getRegistry().containsBeanDefinition(DELEGATING_METHOD_DEFINITION_SOURCE_ID)) {
            parserContext.getReaderContext().error("Duplicate <global-method-security> detected.", source);
        }
        RootBeanDefinition delegatingMethodSecurityMetadataSource = new RootBeanDefinition(DelegatingMethodSecurityMetadataSource.class);
        delegatingMethodSecurityMetadataSource.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        delegatingMethodSecurityMetadataSource.setSource(source);
        delegatingMethodSecurityMetadataSource.getPropertyValues().addPropertyValue("methodSecurityMetadataSources", delegates);
        parserContext.getRegistry().registerBeanDefinition(DELEGATING_METHOD_DEFINITION_SOURCE_ID, delegatingMethodSecurityMetadataSource);
    }

    private void registerProtectPointcutPostProcessor(ParserContext parserContext,
            Map<String, List<ConfigAttribute>> pointcutMap,
            MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource, Object source) {
        RootBeanDefinition ppbp = new RootBeanDefinition(ProtectPointcutPostProcessor.class);
        ppbp.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        ppbp.setSource(source);
        ppbp.getConstructorArgumentValues().addGenericArgumentValue(mapBasedMethodSecurityMetadataSource);
        ppbp.getPropertyValues().addPropertyValue("pointcutMap", pointcutMap);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.PROTECT_POINTCUT_POST_PROCESSOR, ppbp);
    }

    private Map<String, List<ConfigAttribute>> parseProtectPointcuts(ParserContext parserContext, List<Element> protectPointcutElts) {
        Map<String, List<ConfigAttribute>> pointcutMap = new LinkedHashMap<String, List<ConfigAttribute>>();

        for (Element childElt : protectPointcutElts) {
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
        interceptor.getPropertyValues().addPropertyValue("securityMetadataSource", new RuntimeBeanReference(DELEGATING_METHOD_DEFINITION_SOURCE_ID));
        parserContext.getRegistry().registerBeanDefinition(SECURITY_INTERCEPTOR_ID, interceptor);
        parserContext.registerComponent(new BeanComponentDefinition(interceptor, SECURITY_INTERCEPTOR_ID));

        parserContext.getRegistry().registerBeanDefinition(INTERCEPTOR_POST_PROCESSOR_ID,
                new RootBeanDefinition(MethodSecurityInterceptorPostProcessor.class));
    }

    private void registerAdvisor(ParserContext parserContext, Object source) {
        RootBeanDefinition advisor = new RootBeanDefinition(MethodSecurityMetadataSourceAdvisor.class);
        advisor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        advisor.setSource(source);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(SECURITY_INTERCEPTOR_ID);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(new RuntimeBeanReference(DELEGATING_METHOD_DEFINITION_SOURCE_ID));

        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_SECURITY_METADATA_SOURCE_ADVISOR, advisor);
    }
}
