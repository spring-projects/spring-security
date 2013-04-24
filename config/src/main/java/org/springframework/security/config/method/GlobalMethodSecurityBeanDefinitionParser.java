/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.method;

import static org.springframework.security.config.Elements.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.config.AopNamespaceUtils;
import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.annotation.Jsr250Voter;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPostInvocationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PostInvocationAdviceProvider;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Elements;
import org.springframework.security.config.authentication.AuthenticationManagerFactoryBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Processes the top-level "global-method-security" element.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 * @since 2.0
 */
public class GlobalMethodSecurityBeanDefinitionParser implements BeanDefinitionParser {

    private final Log logger = LogFactory.getLog(getClass());

    private static final String ATT_AUTHENTICATION_MANAGER_REF = "authentication-manager-ref";
    private static final String ATT_ACCESS = "access";
    private static final String ATT_EXPRESSION = "expression";
    private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";
    private static final String ATT_RUN_AS_MGR = "run-as-manager-ref";
    private static final String ATT_USE_JSR250 = "jsr250-annotations";
    private static final String ATT_USE_SECURED = "secured-annotations";
    private static final String ATT_USE_PREPOST = "pre-post-annotations";
    private static final String ATT_REF = "ref";
    private static final String ATT_MODE = "mode";
    private static final String ATT_ADVICE_ORDER = "order";
    private static final String ATT_META_DATA_SOURCE_REF = "metadata-source-ref";

    public BeanDefinition parse(Element element, ParserContext pc) {
        CompositeComponentDefinition compositeDef =
            new CompositeComponentDefinition(element.getTagName(), pc.extractSource(element));
        pc.pushContainingComponent(compositeDef);

        Object source = pc.extractSource(element);
        // The list of method metadata delegates
        ManagedList<BeanMetadataElement> delegates = new ManagedList<BeanMetadataElement>();

        boolean jsr250Enabled = "enabled".equals(element.getAttribute(ATT_USE_JSR250));
        boolean useSecured = "enabled".equals(element.getAttribute(ATT_USE_SECURED));
        boolean prePostAnnotationsEnabled = "enabled".equals(element.getAttribute(ATT_USE_PREPOST));
        boolean useAspectJ = "aspectj".equals(element.getAttribute(ATT_MODE));

        BeanDefinition preInvocationVoter = null;
        ManagedList<BeanMetadataElement> afterInvocationProviders = new ManagedList<BeanMetadataElement>();

        // Check for an external SecurityMetadataSource, which takes priority over other sources
        String metaDataSourceId = element.getAttribute(ATT_META_DATA_SOURCE_REF);

        if (StringUtils.hasText(metaDataSourceId)) {
            delegates.add(new RuntimeBeanReference(metaDataSourceId));
        }

        if (prePostAnnotationsEnabled) {
            Element prePostElt = DomUtils.getChildElementByTagName(element, INVOCATION_HANDLING);
            Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, EXPRESSION_HANDLER);

            if (prePostElt != null && expressionHandlerElt != null) {
                pc.getReaderContext().error(INVOCATION_HANDLING + " and " +
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
                    RootBeanDefinition lazyInitPP = new RootBeanDefinition(LazyInitBeanDefinitionRegistryPostProcessor.class);
                    lazyInitPP.getConstructorArgumentValues().addGenericArgumentValue(expressionHandlerRef);
                    pc.getReaderContext().registerWithGeneratedName(lazyInitPP);

                    BeanDefinitionBuilder lazyMethodSecurityExpressionHandlerBldr = BeanDefinitionBuilder.rootBeanDefinition(LazyInitTargetSource.class);
                    lazyMethodSecurityExpressionHandlerBldr.addPropertyValue("targetBeanName", expressionHandlerRef);

                    BeanDefinitionBuilder expressionHandlerProxyBldr = BeanDefinitionBuilder.rootBeanDefinition(ProxyFactoryBean.class);
                    expressionHandlerProxyBldr.addPropertyValue("targetSource", lazyMethodSecurityExpressionHandlerBldr.getBeanDefinition());
                    expressionHandlerProxyBldr.addPropertyValue("proxyInterfaces", MethodSecurityExpressionHandler.class);

                    expressionHandlerRef = pc.getReaderContext().generateBeanName(expressionHandlerProxyBldr.getBeanDefinition());

                    pc.registerBeanComponent(new BeanComponentDefinition(expressionHandlerProxyBldr.getBeanDefinition(), expressionHandlerRef));
                } else {
                    BeanDefinition expressionHandler = new RootBeanDefinition(DefaultMethodSecurityExpressionHandler.class);
                    expressionHandlerRef = pc.getReaderContext().generateBeanName(expressionHandler);
                    pc.registerBeanComponent(new BeanComponentDefinition(expressionHandler, expressionHandlerRef));
                    logger.info("Expressions were enabled for method security but no SecurityExpressionHandler was configured. " +
                            "All hasPermision() expressions will evaluate to false.");
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
            afterInvocationProviders.add(afterInvocationBldr.getBeanDefinition());
            delegates.add(mds.getBeanDefinition());
        }

        if (useSecured) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(SecuredAnnotationSecurityMetadataSource.class).getBeanDefinition());
        }

        if (jsr250Enabled) {
            delegates.add(BeanDefinitionBuilder.rootBeanDefinition(Jsr250MethodSecurityMetadataSource.class).getBeanDefinition());
        }

        // Now create a Map<String, ConfigAttribute> for each <protect-pointcut> sub-element
        Map<String, List<ConfigAttribute>> pointcutMap = parseProtectPointcuts(pc,
                DomUtils.getChildElementsByTagName(element, PROTECT_POINTCUT));

        if (pointcutMap.size() > 0) {
            if (useAspectJ) {
                pc.getReaderContext().error("You can't use AspectJ mode with protect-pointcut definitions", source);
            }
            // Only add it if there are actually any pointcuts defined.
            BeanDefinition mapBasedMetadataSource = new RootBeanDefinition(MapBasedMethodSecurityMetadataSource.class);
            BeanReference ref = new RuntimeBeanReference(pc.getReaderContext().generateBeanName(mapBasedMetadataSource));

            delegates.add(ref);
            pc.registerBeanComponent(new BeanComponentDefinition(mapBasedMetadataSource, ref.getBeanName()));
            registerProtectPointcutPostProcessor(pc, pointcutMap, ref, source);
        }

        BeanReference metadataSource = registerDelegatingMethodSecurityMetadataSource(pc, delegates, source);

        // Check for additional after-invocation-providers..
        List<Element> afterInvocationElts = DomUtils.getChildElementsByTagName(element, Elements.AFTER_INVOCATION_PROVIDER);

        for (Element elt : afterInvocationElts) {
            afterInvocationProviders.add(new RuntimeBeanReference(elt.getAttribute(ATT_REF)));
        }

        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            accessManagerId = registerAccessManager(pc, jsr250Enabled, preInvocationVoter);
        }

        String authMgrRef = element.getAttribute(ATT_AUTHENTICATION_MANAGER_REF);

        String runAsManagerId = element.getAttribute(ATT_RUN_AS_MGR);
        BeanReference interceptor = registerMethodSecurityInterceptor(pc, authMgrRef, accessManagerId, runAsManagerId,
                metadataSource, afterInvocationProviders, source, useAspectJ);

        if (useAspectJ) {
            BeanDefinitionBuilder aspect =
                BeanDefinitionBuilder.rootBeanDefinition("org.springframework.security.access.intercept.aspectj.aspect.AnnotationSecurityAspect");
            aspect.setFactoryMethod("aspectOf");
            aspect.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            aspect.addPropertyValue("securityInterceptor", interceptor);
            String id = pc.getReaderContext().registerWithGeneratedName(aspect.getBeanDefinition());
            pc.registerBeanComponent(new BeanComponentDefinition(aspect.getBeanDefinition(), id));
        } else {
            registerAdvisor(pc, interceptor, metadataSource, source, element.getAttribute(ATT_ADVICE_ORDER));
            AopNamespaceUtils.registerAutoProxyCreatorIfNecessary(pc, element);
        }

        pc.popAndRegisterContainingComponent();

        return null;
    }

    /**
     * Register the default AccessDecisionManager. Adds the special JSR 250 voter jsr-250 is enabled and an
     * expression voter if expression-based access control is enabled.
     * @return
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private String registerAccessManager(ParserContext pc, boolean jsr250Enabled, BeanDefinition expressionVoter) {

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

        accessMgrBuilder.addConstructorArgValue(voters);

        BeanDefinition accessManager = accessMgrBuilder.getBeanDefinition();
        String id = pc.getReaderContext().generateBeanName(accessManager);
        pc.registerBeanComponent(new BeanComponentDefinition(accessManager, id));

        return id;
    }

    @SuppressWarnings("rawtypes")
    private BeanReference registerDelegatingMethodSecurityMetadataSource(ParserContext pc, ManagedList delegates, Object source) {
        RootBeanDefinition delegatingMethodSecurityMetadataSource = new RootBeanDefinition(DelegatingMethodSecurityMetadataSource.class);
        delegatingMethodSecurityMetadataSource.setSource(source);
        delegatingMethodSecurityMetadataSource.getConstructorArgumentValues().addGenericArgumentValue(delegates);

        String id = pc.getReaderContext().generateBeanName(delegatingMethodSecurityMetadataSource);
        pc.registerBeanComponent(new BeanComponentDefinition(delegatingMethodSecurityMetadataSource, id));

        return new RuntimeBeanReference(id);
    }

    private void registerProtectPointcutPostProcessor(ParserContext parserContext,
            Map<String, List<ConfigAttribute>> pointcutMap,
            BeanReference mapBasedMethodSecurityMetadataSource, Object source) {
        RootBeanDefinition ppbp = new RootBeanDefinition(ProtectPointcutPostProcessor.class);
        ppbp.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        ppbp.setSource(source);
        ppbp.getConstructorArgumentValues().addGenericArgumentValue(mapBasedMethodSecurityMetadataSource);
        ppbp.getPropertyValues().addPropertyValue("pointcutMap", pointcutMap);
        parserContext.getReaderContext().registerWithGeneratedName(ppbp);
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

    private BeanReference registerMethodSecurityInterceptor(ParserContext pc, String authMgrRef, String accessManagerId,
            String runAsManagerId, BeanReference metadataSource,
            List<BeanMetadataElement> afterInvocationProviders, Object source, boolean useAspectJ) {
        BeanDefinitionBuilder bldr =
            BeanDefinitionBuilder.rootBeanDefinition(useAspectJ ?
                    AspectJMethodSecurityInterceptor.class : MethodSecurityInterceptor.class);
        bldr.getRawBeanDefinition().setSource(source);
        bldr.addPropertyReference("accessDecisionManager", accessManagerId);
        RootBeanDefinition authMgr = new RootBeanDefinition(AuthenticationManagerDelegator.class);
        authMgr.getConstructorArgumentValues().addGenericArgumentValue(authMgrRef);
        bldr.addPropertyValue("authenticationManager", authMgr);
        bldr.addPropertyValue("securityMetadataSource", metadataSource);

        if (StringUtils.hasText(runAsManagerId)) {
            bldr.addPropertyReference("runAsManager", runAsManagerId);
        }

        if (!afterInvocationProviders.isEmpty()) {
            BeanDefinition afterInvocationManager;
            afterInvocationManager = new RootBeanDefinition(AfterInvocationProviderManager.class);
            afterInvocationManager.getPropertyValues().addPropertyValue("providers", afterInvocationProviders);
            bldr.addPropertyValue("afterInvocationManager", afterInvocationManager);
        }

        BeanDefinition bean = bldr.getBeanDefinition();
        String id = pc.getReaderContext().generateBeanName(bean);
        pc.registerBeanComponent(new BeanComponentDefinition(bean, id));

        return new RuntimeBeanReference(id);
    }

    private void registerAdvisor(ParserContext parserContext, BeanReference interceptor, BeanReference metadataSource, Object source, String adviceOrder) {
        if (parserContext.getRegistry().containsBeanDefinition(BeanIds.METHOD_SECURITY_METADATA_SOURCE_ADVISOR)) {
            parserContext.getReaderContext().error("Duplicate <global-method-security> detected.", source);
        }
        RootBeanDefinition advisor = new RootBeanDefinition(MethodSecurityMetadataSourceAdvisor.class);

        if (StringUtils.hasText(adviceOrder)) {
            advisor.getPropertyValues().addPropertyValue("order", adviceOrder);
        }

        // advisor must be an infrastructure bean as Spring's InfrastructureAdvisorAutoProxyCreator will ignore it
        // otherwise
        advisor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        advisor.setSource(source);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(interceptor.getBeanName());
        advisor.getConstructorArgumentValues().addGenericArgumentValue(metadataSource);
        advisor.getConstructorArgumentValues().addGenericArgumentValue(metadataSource.getBeanName());

        parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_SECURITY_METADATA_SOURCE_ADVISOR, advisor);
    }

    /**
     * Delays the lookup of the AuthenticationManager within MethodSecurityInterceptor, to prevent issues like SEC-933.
     *
     * @author Luke Taylor
     * @since 3.0
     */
    static final class AuthenticationManagerDelegator implements AuthenticationManager, BeanFactoryAware {
        private AuthenticationManager delegate;
        private final Object delegateMonitor = new Object();
        private BeanFactory beanFactory;
        private final String authMgrBean;

        AuthenticationManagerDelegator(String authMgrBean) {
            this.authMgrBean = StringUtils.hasText(authMgrBean) ? authMgrBean : BeanIds.AUTHENTICATION_MANAGER;
        }

        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            synchronized(delegateMonitor) {
                if (delegate == null) {
                    Assert.state(beanFactory != null, "BeanFactory must be set to resolve " + authMgrBean);
                    try {
                        delegate = beanFactory.getBean(authMgrBean, AuthenticationManager.class);
                    } catch (NoSuchBeanDefinitionException e) {
                        if (BeanIds.AUTHENTICATION_MANAGER.equals(e.getBeanName())) {
                            throw new NoSuchBeanDefinitionException(BeanIds.AUTHENTICATION_MANAGER,
                                AuthenticationManagerFactoryBean.MISSING_BEAN_ERROR_MESSAGE);
                        }
                        throw e;
                    }
                }
            }

            return delegate.authenticate(authentication);
        }

        public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
            this.beanFactory = beanFactory;
        }
    }

    /**
     * Delays setting a bean of a given name to be lazyily initialized until after all the beans are registered.
     *
     * @author Rob Winch
     * @since 3.2
     */
    private static final class LazyInitBeanDefinitionRegistryPostProcessor implements BeanDefinitionRegistryPostProcessor {
        private final String beanName;

        private LazyInitBeanDefinitionRegistryPostProcessor(String beanName) {
            this.beanName = beanName;
        }

        public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
            BeanDefinition beanDefinition = registry.getBeanDefinition(beanName);
            beanDefinition.setLazyInit(true);
        }

        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        }
    }
}
