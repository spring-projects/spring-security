package org.springframework.security.config;

import static org.springframework.security.config.Elements.*;

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
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.annotation.Jsr250Voter;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPostInvocationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PostInvocationAdviceProvider;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
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
    private static final String ATT_RUN_AS_MGR = "run-as-manager-ref";
    private static final String ATT_USE_JSR250 = "jsr250-annotations";
    private static final String ATT_USE_SECURED = "secured-annotations";
    private static final String ATT_USE_PREPOST = "pre-post-annotations";

    @SuppressWarnings("unchecked")
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        Object source = parserContext.extractSource(element);
        // The list of method metadata delegates
        ManagedList delegates = new ManagedList();

        boolean jsr250Enabled = "enabled".equals(element.getAttribute(ATT_USE_JSR250));
        boolean useSecured = "enabled".equals(element.getAttribute(ATT_USE_SECURED));
        boolean prePostAnnotationsEnabled = "enabled".equals(element.getAttribute(ATT_USE_PREPOST));
        BeanDefinition preInvocationVoter = null;

        if (prePostAnnotationsEnabled) {
            Element prePostElt = DomUtils.getChildElementByTagName(element, INVOCATION_HANDLING);
            Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, EXPRESSION_HANDLER);

            if (prePostElt != null && expressionHandlerElt != null) {
                parserContext.getReaderContext().error(INVOCATION_HANDLING + " and " +
                        EXPRESSION_HANDLER + " cannot be used together ", source);
            }

            BeanDefinitionBuilder preInvocationVoterBldr = BeanDefinitionBuilder.rootBeanDefinition(PreInvocationAuthorizationAdviceVoter.class);
            // After-invocation provider to handle post-invocation filtering and authorization expression annotations.
            BeanDefinitionBuilder afterInvocationBldr = BeanDefinitionBuilder.rootBeanDefinition(PostInvocationAdviceProvider.class);
            // The metadata source for the security interceptor
            BeanDefinitionBuilder mds = BeanDefinitionBuilder.rootBeanDefinition(PrePostAnnotationSecurityMetadataSource.class);

            if (prePostElt != null) {
                // Customized override of expression handling system
                String attributeFactoryRef =
                    DomUtils.getChildElementByTagName(prePostElt, INVOCATION_ATTRIBUTE_FACTORY).getAttribute("ref");
                String preAdviceRef =
                    DomUtils.getChildElementByTagName(prePostElt, PRE_INVOCATION_ADVICE).getAttribute("ref");
                String postAdviceRef =
                    DomUtils.getChildElementByTagName(prePostElt, POST_INVOCATION_ADVICE).getAttribute("ref");

                mds.addConstructorArgReference(attributeFactoryRef);
                preInvocationVoterBldr.addConstructorArgReference(preAdviceRef);
                afterInvocationBldr.addConstructorArgReference(postAdviceRef);
            } else {
                // The default expression-based system
                String expressionHandlerRef = expressionHandlerElt == null ? null : expressionHandlerElt.getAttribute("ref");

                if (StringUtils.hasText(expressionHandlerRef)) {
                    logger.info("Using bean '" + expressionHandlerRef + "' as method ExpressionHandler implementation");
                } else {
                    parserContext.getRegistry().registerBeanDefinition(EXPRESSION_HANDLER_ID, new RootBeanDefinition(DefaultMethodSecurityExpressionHandler.class));
                    logger.warn("Expressions were enabled for method security but no SecurityExpressionHandler was configured. " +
                            "All hasPermision() expressions will evaluate to false.");
                    expressionHandlerRef = EXPRESSION_HANDLER_ID;
                }

                BeanDefinitionBuilder expressionPreAdviceBldr = BeanDefinitionBuilder.rootBeanDefinition(ExpressionBasedPreInvocationAdvice.class);
                expressionPreAdviceBldr.addPropertyReference("expressionHandler", expressionHandlerRef);
                preInvocationVoterBldr.addConstructorArgValue(expressionPreAdviceBldr.getBeanDefinition());

                BeanDefinitionBuilder expressionPostAdviceBldr = BeanDefinitionBuilder.rootBeanDefinition(ExpressionBasedPostInvocationAdvice.class);
                expressionPostAdviceBldr.addConstructorArgReference(expressionHandlerRef);
                afterInvocationBldr.addConstructorArgValue(expressionPostAdviceBldr.getBeanDefinition());

                BeanDefinitionBuilder annotationInvocationFactory = BeanDefinitionBuilder.rootBeanDefinition(ExpressionBasedAnnotationAttributeFactory.class);
                annotationInvocationFactory.addConstructorArgReference(expressionHandlerRef);
                mds.addConstructorArgValue(annotationInvocationFactory.getBeanDefinition());
            }

            preInvocationVoter = preInvocationVoterBldr.getBeanDefinition();
            ConfigUtils.getRegisteredAfterInvocationProviders(parserContext).add(afterInvocationBldr.getBeanDefinition());
            delegates.add(mds.getBeanDefinition());
        }

        if (useSecured) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(SecuredAnnotationSecurityMetadataSource.class).getBeanDefinition());
        }

        if (jsr250Enabled) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(Jsr250MethodSecurityMetadataSource.class).getBeanDefinition());
        }

        // Now create a Map<String, ConfigAttribute> for each <protect-pointcut> sub-element
        Map<String, List<ConfigAttribute>> pointcutMap = parseProtectPointcuts(parserContext,
                DomUtils.getChildElementsByTagName(element, PROTECT_POINTCUT));

        if (pointcutMap.size() > 0) {
            // Only add it if there are actually any pointcuts defined.
            MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource = new MapBasedMethodSecurityMetadataSource();
            delegates.add(mapBasedMethodSecurityMetadataSource);
            registerProtectPointcutPostProcessor(parserContext, pointcutMap, mapBasedMethodSecurityMetadataSource, source);
        }

        registerDelegatingMethodSecurityMetadataSource(parserContext, delegates, source);

        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            registerAccessManager(parserContext, jsr250Enabled, preInvocationVoter);
            accessManagerId = ACCESS_MANAGER_ID;
        }

        String runAsManagerId = element.getAttribute(ATT_RUN_AS_MGR);

        registerMethodSecurityInterceptor(parserContext, accessManagerId, runAsManagerId, source);

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
            voters.add(new RootBeanDefinition(Jsr250Voter.class));
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

    private void registerMethodSecurityInterceptor(ParserContext pc, String accessManagerId, String runAsManagerId, Object source) {
        BeanDefinitionBuilder bldr = BeanDefinitionBuilder.rootBeanDefinition(MethodSecurityInterceptor.class);
        bldr.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        bldr.getRawBeanDefinition().setSource(source);

        bldr.addPropertyReference("accessDecisionManager", accessManagerId);
        bldr.addPropertyReference("authenticationManager", BeanIds.AUTHENTICATION_MANAGER);
        bldr.addPropertyReference("securityMetadataSource", DELEGATING_METHOD_DEFINITION_SOURCE_ID);
        if (StringUtils.hasText(runAsManagerId)) {
            bldr.addPropertyReference("runAsManager", runAsManagerId);
        }

        BeanDefinition interceptor = bldr.getBeanDefinition();
        pc.getRegistry().registerBeanDefinition(SECURITY_INTERCEPTOR_ID, interceptor);
        pc.registerComponent(new BeanComponentDefinition(interceptor, SECURITY_INTERCEPTOR_ID));

        pc.getRegistry().registerBeanDefinition(INTERCEPTOR_POST_PROCESSOR_ID,
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
