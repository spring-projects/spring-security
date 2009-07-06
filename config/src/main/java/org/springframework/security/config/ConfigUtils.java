package org.springframework.security.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Utility methods used internally by the Spring Security namespace configuration code.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
abstract class ConfigUtils {

    @SuppressWarnings("unchecked")
    static void registerDefaultMethodAccessManagerIfNecessary(ParserContext parserContext) {
        if (!parserContext.getRegistry().containsBeanDefinition(BeanIds.METHOD_ACCESS_MANAGER)) {
            parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_ACCESS_MANAGER,
                    createAccessManagerBean(RoleVoter.class, AuthenticatedVoter.class));
        }
    }

    @SuppressWarnings("unchecked")
    static RootBeanDefinition createAccessManagerBean(Class<? extends AccessDecisionVoter>... voters) {
        ManagedList defaultVoters = new ManagedList(voters.length);

        for(Class<? extends AccessDecisionVoter> voter : voters) {
            defaultVoters.add(new RootBeanDefinition(voter));
        }

        BeanDefinitionBuilder accessMgrBuilder = BeanDefinitionBuilder.rootBeanDefinition(AffirmativeBased.class);
        accessMgrBuilder.addPropertyValue("decisionVoters", defaultVoters);
        return (RootBeanDefinition) accessMgrBuilder.getBeanDefinition();
    }

    public static int countNonEmpty(String[] objects) {
        int nonNulls = 0;

        for (int i = 0; i < objects.length; i++) {
            if (StringUtils.hasText(objects[i])) {
                nonNulls++;
            }
        }

        return nonNulls;
    }

    /**
     * Creates and registers the bean definition for the default ProviderManager instance and returns
     * the BeanDefinition for it. This method will typically be called when registering authentication providers
     * using the &lt;security:provider /> tag or by other beans which have a dependency on the
     * authentication manager.
     * @param element the source element under which this bean should be registered.
     */
    static void registerProviderManagerIfNecessary(ParserContext pc, Element element) {

        if(pc.getRegistry().containsBeanDefinition(BeanIds.AUTHENTICATION_MANAGER)) {
            return;
        }

        RootBeanDefinition authManager = new RootBeanDefinition(NamespaceAuthenticationManager.class);
        authManager.getPropertyValues().addPropertyValue("providerBeanNames", new ArrayList<String>());
        authManager.setSource(pc.extractSource(element.getOwnerDocument().getFirstChild()));
        pc.getRegistry().registerBeanDefinition(BeanIds.AUTHENTICATION_MANAGER, authManager);
        pc.registerBeanComponent(new BeanComponentDefinition(authManager, BeanIds.AUTHENTICATION_MANAGER));
    }

    @SuppressWarnings("unchecked")
    static void addAuthenticationProvider(ParserContext parserContext, String beanName, Element element) {
        registerProviderManagerIfNecessary(parserContext, element);
        BeanDefinition authManager = parserContext.getRegistry().getBeanDefinition(BeanIds.AUTHENTICATION_MANAGER);
        ((ArrayList) authManager.getPropertyValues().getPropertyValue("providerBeanNames").getValue()).add(beanName);
    }

    @SuppressWarnings("unchecked")
    static ManagedList getRegisteredAfterInvocationProviders(ParserContext parserContext) {
        BeanDefinition manager = registerAfterInvocationProviderManagerIfNecessary(parserContext);
        return (ManagedList) manager.getPropertyValues().getPropertyValue("providers").getValue();
    }

    @SuppressWarnings("unchecked")
    private static BeanDefinition registerAfterInvocationProviderManagerIfNecessary(ParserContext parserContext) {
        if(parserContext.getRegistry().containsBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER)) {
            return parserContext.getRegistry().getBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER);
        }

        BeanDefinition manager = new RootBeanDefinition(AfterInvocationProviderManager.class);
        manager.getPropertyValues().addPropertyValue("providers", new ManagedList());
        parserContext.getRegistry().registerBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER, manager);

        return manager;
    }

//    private static void registerFilterChainPostProcessorIfNecessary(ParserContext pc) {
//        if (pc.getRegistry().containsBeanDefinition(BeanIds.FILTER_CHAIN_POST_PROCESSOR)) {
//            return;
//        }
//        // Post processor specifically to assemble and order the filter chain immediately before the FilterChainProxy is initialized.
//        RootBeanDefinition filterChainPostProcessor = new RootBeanDefinition(FilterChainProxyPostProcessor.class);
//        filterChainPostProcessor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
//        pc.getRegistry().registerBeanDefinition(BeanIds.FILTER_CHAIN_POST_PROCESSOR, filterChainPostProcessor);
//        RootBeanDefinition filterList = new RootBeanDefinition(FilterChainList.class);
//        filterList.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
//        pc.getRegistry().registerBeanDefinition(BeanIds.FILTER_LIST, filterList);
//        pc.registerBeanComponent(new BeanComponentDefinition(filterList, BeanIds.FILTER_LIST));
//    }

 //   @SuppressWarnings("unchecked")
//    static void addHttpFilter(ParserContext pc, BeanMetadataElement filter) {
//        registerFilterChainPostProcessorIfNecessary(pc);
//
//        RootBeanDefinition filterList = (RootBeanDefinition) pc.getRegistry().getBeanDefinition(BeanIds.FILTER_LIST);
//
//        ManagedList filters;
//        MutablePropertyValues pvs = filterList.getPropertyValues();
//        if (pvs.contains("filters")) {
//            filters = (ManagedList) pvs.getPropertyValue("filters").getValue();
//        } else {
//            filters = new ManagedList();
//            pvs.addPropertyValue("filters", filters);
//        }
//
//        filters.add(filter);
//    }

    /**
     * Checks the value of an XML attribute which represents a redirect URL.
     * If not empty or starting with "$" (potential placeholder), "/" or "http" it will raise an error.
     */
    static void validateHttpRedirect(String url, ParserContext pc, Object source) {
        if (!StringUtils.hasText(url) || UrlUtils.isValidRedirectUrl(url) || url.startsWith("$")) {
            return;
        }
        pc.getReaderContext().warning(url + " is not a valid redirect URL (must start with '/' or http(s))", source);
    }

    static void setSessionControllerOnAuthenticationManager(ParserContext pc, String beanName, Element sourceElt) {
        BeanDefinition authManager = pc.getRegistry().getBeanDefinition(BeanIds.AUTHENTICATION_MANAGER);
        PropertyValue pv = authManager.getPropertyValues().getPropertyValue("sessionController");

        if (pv != null && pv.getValue() != null) {
            pc.getReaderContext().error("A session controller has already been set on the authentication manager. " +
                    "The <concurrent-session-control> element isn't compatible with a custom session controller",
                    pc.extractSource(sourceElt));
        }

        authManager.getPropertyValues().addPropertyValue("sessionController", new RuntimeBeanReference(beanName));
    }
}
