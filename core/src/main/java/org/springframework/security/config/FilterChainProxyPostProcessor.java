package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.config.ConfigUtils.FilterChainList;
import org.springframework.security.context.SecurityContextPersistenceFilter;
import org.springframework.security.intercept.web.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.providers.anonymous.AnonymousAuthenticationToken;
import org.springframework.security.providers.anonymous.AnonymousProcessingFilter;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.ui.SessionFixationProtectionFilter;
import org.springframework.security.ui.basicauth.BasicProcessingFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.springframework.security.ui.webapp.DefaultLoginPageGeneratingFilter;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.wrapper.SecurityContextHolderAwareRequestFilter;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class FilterChainProxyPostProcessor implements BeanPostProcessor, BeanFactoryAware {
    private Log logger = LogFactory.getLog(getClass());

    private ListableBeanFactory beanFactory;

    @SuppressWarnings("unchecked")
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if(!BeanIds.FILTER_CHAIN_PROXY.equals(beanName)) {
            return bean;
        }

        FilterChainProxy filterChainProxy = (FilterChainProxy) bean;
        FilterChainList filterList = (FilterChainList) beanFactory.getBean(BeanIds.FILTER_LIST);

        List<Filter> filters = new ArrayList<Filter>(filterList.getFilters());
        Collections.sort(filters, new OrderComparator());

        logger.info("Checking sorted filter chain: " + filters);

        for(int i=0; i < filters.size(); i++) {
            Ordered filter = (Ordered)filters.get(i);

            if (i > 0) {
                Ordered previous = (Ordered)filters.get(i-1);
                if (filter.getOrder() == previous.getOrder()) {
                    throw new SecurityConfigurationException("Filters '" + unwrapFilter(filter) + "' and '" +
                            unwrapFilter(previous) + "' have the same 'order' value. When using custom filters, " +
                                    "please make sure the positions do not conflict with default filters. " +
                                    "Alternatively you can disable the default filters by removing the corresponding " +
                                    "child elements from <http> and avoiding the use of <http auto-config='true'>.");
                }
            }
        }

        logger.info("Filter chain...");
        for (int i=0; i < filters.size(); i++) {
        // Remove the ordered wrapper from the filter and put it back in the chain at the same position.
            Filter filter = unwrapFilter(filters.get(i));
            logger.info("[" + i + "] - " + filter);
            filters.set(i, filter);
        }

        checkFilterStack(filters);

        // Note that this returns a copy
        Map<String, List<Filter>> filterMap = filterChainProxy.getFilterChainMap();
        filterMap.put(filterChainProxy.getMatcher().getUniversalMatchPattern(), filters);
        filterChainProxy.setFilterChainMap(filterMap);

        checkLoginPageIsntProtected(filterChainProxy);

        logger.info("FilterChainProxy: " + filterChainProxy);

        return bean;
    }

    /**
     * Checks the filter list for possible errors and logs them
     */
    private void checkFilterStack(List<Filter> filters) {
        checkForDuplicates(SecurityContextPersistenceFilter.class, filters);
        checkForDuplicates(AuthenticationProcessingFilter.class, filters);
        checkForDuplicates(SessionFixationProtectionFilter.class, filters);
        checkForDuplicates(BasicProcessingFilter.class, filters);
        checkForDuplicates(SecurityContextHolderAwareRequestFilter.class, filters);
        checkForDuplicates(ExceptionTranslationFilter.class, filters);
        checkForDuplicates(FilterSecurityInterceptor.class, filters);
    }

    private void checkForDuplicates(Class<? extends Filter> clazz, List<Filter> filters) {
        for (int i=0; i < filters.size(); i++) {
            Filter f1 = filters.get(i);
            if (clazz.isAssignableFrom(f1.getClass())) {
                // Found the first one, check remaining for another
                for (int j=i+1; j < filters.size(); j++) {
                    Filter f2 = filters.get(j);
                    if (clazz.isAssignableFrom(f2.getClass())) {
                        logger.warn("Possible error: Filters at position " + i + " and " + j + " are both " +
                                "instances of " + clazz.getName());
                        return;
                    }
                }
            }
        }
    }

    /* Checks for the common error of having a login page URL protected by the security interceptor */
    private void checkLoginPageIsntProtected(FilterChainProxy fcp) {
        ExceptionTranslationFilter etf = (ExceptionTranslationFilter) beanFactory.getBean(BeanIds.EXCEPTION_TRANSLATION_FILTER);

        if (etf.getAuthenticationEntryPoint() instanceof AuthenticationProcessingFilterEntryPoint) {
            String loginPage =
                ((AuthenticationProcessingFilterEntryPoint)etf.getAuthenticationEntryPoint()).getLoginFormUrl();
            List<Filter> filters = fcp.getFilters(loginPage);
            logger.info("Checking whether login URL '" + loginPage + "' is accessible with your configuration");

            if (filters == null || filters.isEmpty()) {
                logger.debug("Filter chain is empty for the login page");
                return;
            }

            if (loginPage.equals(DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL) &&
                    beanFactory.containsBean(BeanIds.DEFAULT_LOGIN_PAGE_GENERATING_FILTER)) {
                logger.debug("Default generated login page is in use");
                return;
            }

            FilterSecurityInterceptor fsi =
                    ((FilterSecurityInterceptor)beanFactory.getBean(BeanIds.FILTER_SECURITY_INTERCEPTOR));
            DefaultFilterInvocationSecurityMetadataSource fids =
                    (DefaultFilterInvocationSecurityMetadataSource) fsi.getSecurityMetadataSource();
            List<ConfigAttribute> attributes = fids.lookupAttributes(loginPage, "POST");

            if (attributes == null) {
                logger.debug("No access attributes defined for login page URL");
                if (fsi.isRejectPublicInvocations()) {
                    logger.warn("FilterSecurityInterceptor is configured to reject public invocations." +
                            " Your login page may not be accessible.");
                }
                return;
            }

            if (!beanFactory.containsBean(BeanIds.ANONYMOUS_PROCESSING_FILTER)) {
                logger.warn("The login page is being protected by the filter chain, but you don't appear to have" +
                        " anonymous authentication enabled. This is almost certainly an error.");
                return;
            }

            // Simulate an anonymous access with the supplied attributes.
            AnonymousProcessingFilter anonPF = (AnonymousProcessingFilter) beanFactory.getBean(BeanIds.ANONYMOUS_PROCESSING_FILTER);
            AnonymousAuthenticationToken token =
                    new AnonymousAuthenticationToken("key", anonPF.getUserAttribute().getPassword(),
                            anonPF.getUserAttribute().getAuthorities());
            try {
                fsi.getAccessDecisionManager().decide(token, new Object(), fids.lookupAttributes(loginPage, "POST"));
            } catch (Exception e) {
                logger.warn("Anonymous access to the login page doesn't appear to be enabled. This is almost certainly " +
                        "an error. Please check your configuration allows unauthenticated access to the configured " +
                        "login page. (Simulated access was rejected: " + e + ")");
            }
        }
    }

    /**
     * Returns the delegate filter of a wrapper, or the unchanged filter if it isn't wrapped.
     */
    private Filter unwrapFilter(Object filter) {
        if (filter instanceof OrderedFilterBeanDefinitionDecorator.OrderedFilterDecorator) {
            return ((OrderedFilterBeanDefinitionDecorator.OrderedFilterDecorator)filter).getDelegate();
        }

        return (Filter) filter;
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = (ListableBeanFactory) beanFactory;
    }
}
