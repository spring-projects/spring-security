package org.springframework.security.config.http;

import java.util.*;

import javax.servlet.Filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.AnyRequestMatcher;

public class DefaultFilterChainValidator implements FilterChainProxy.FilterChainValidator {
    private final Log logger = LogFactory.getLog(getClass());

    public void validate(FilterChainProxy fcp) {
        for(SecurityFilterChain filterChain : fcp.getFilterChains()) {
            checkLoginPageIsntProtected(fcp, filterChain.getFilters());
            checkFilterStack(filterChain.getFilters());
        }

        checkPathOrder(new ArrayList<SecurityFilterChain>(fcp.getFilterChains()));
        checkForDuplicateMatchers(new ArrayList<SecurityFilterChain>(fcp.getFilterChains()));
    }

    private void checkPathOrder(List<SecurityFilterChain> filterChains) {
        // Check that the universal pattern is listed at the end, if at all
        Iterator<SecurityFilterChain> chains = filterChains.iterator();

        while (chains.hasNext()) {
            if (((DefaultSecurityFilterChain)chains.next()).getRequestMatcher() instanceof AnyRequestMatcher && chains.hasNext()) {
                throw new IllegalArgumentException("A universal match pattern ('/**') is defined " +
                        " before other patterns in the filter chain, causing them to be ignored. Please check the " +
                        "ordering in your <security:http> namespace or FilterChainProxy bean configuration");
            }
        }
    }

    private void checkForDuplicateMatchers(List<SecurityFilterChain> chains) {

        while (chains.size() > 1) {
            DefaultSecurityFilterChain chain = (DefaultSecurityFilterChain)chains.remove(0);

            for (SecurityFilterChain test : chains) {
                if (chain.getRequestMatcher().equals(((DefaultSecurityFilterChain)test).getRequestMatcher())) {
                    throw new IllegalArgumentException("The FilterChainProxy contains two filter chains using the" +
                            " matcher " + chain.getRequestMatcher() + ". If you are using multiple <http> namespace " +
                            "elements, you must use a 'pattern' attribute to define the request patterns to which they apply.");
                }
            }
        }
    }

    @SuppressWarnings({"unchecked"})
    private <F extends Filter> F getFilter(Class<F> type, List<Filter> filters) {
        for (Filter f : filters) {
            if (type.isAssignableFrom(f.getClass())) {
                return (F) f;
            }
        }

        return null;
    }

    /**
     * Checks the filter list for possible errors and logs them
     */
    private void checkFilterStack(List<Filter> filters) {
        checkForDuplicates(SecurityContextPersistenceFilter.class, filters);
        checkForDuplicates(UsernamePasswordAuthenticationFilter.class, filters);
        checkForDuplicates(SessionManagementFilter.class, filters);
        checkForDuplicates(BasicAuthenticationFilter.class, filters);
        checkForDuplicates(SecurityContextHolderAwareRequestFilter.class, filters);
        checkForDuplicates(JaasApiIntegrationFilter.class, filters);
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
    private void checkLoginPageIsntProtected(FilterChainProxy fcp, List<Filter> filterStack) {
        ExceptionTranslationFilter etf = getFilter(ExceptionTranslationFilter.class, filterStack);

        if(etf == null || !(etf.getAuthenticationEntryPoint() instanceof LoginUrlAuthenticationEntryPoint)) {
            return;
        }

        String loginPage = ((LoginUrlAuthenticationEntryPoint)etf.getAuthenticationEntryPoint()).getLoginFormUrl();
        logger.info("Checking whether login URL '" + loginPage + "' is accessible with your configuration");
        FilterInvocation loginRequest = new FilterInvocation(loginPage, "POST");
        List<Filter> filters = null;

        try {
            filters = fcp.getFilters(loginPage);
        } catch (Exception e) {
            // May happen legitimately if a filter-chain request matcher requires more request data than that provided
            // by the dummy request used when creating the filter invocation.
            logger.info("Failed to obtain filter chain information for the login page. Unable to complete check.");
        }

        if (filters == null || filters.isEmpty()) {
            logger.debug("Filter chain is empty for the login page");
            return;
        }

        if (getFilter(DefaultLoginPageGeneratingFilter.class, filters) != null) {
            logger.debug("Default generated login page is in use");
            return;
        }

        FilterSecurityInterceptor fsi = getFilter(FilterSecurityInterceptor.class, filters);
        DefaultFilterInvocationSecurityMetadataSource fids =
                (DefaultFilterInvocationSecurityMetadataSource) fsi.getSecurityMetadataSource();

        Collection<ConfigAttribute> attributes = fids.getAttributes(loginRequest);

        if (attributes == null) {
            logger.debug("No access attributes defined for login page URL");
            if (fsi.isRejectPublicInvocations()) {
                logger.warn("FilterSecurityInterceptor is configured to reject public invocations." +
                        " Your login page may not be accessible.");
            }
            return;
        }

        AnonymousAuthenticationFilter anonPF = getFilter(AnonymousAuthenticationFilter.class, filters);
        if (anonPF == null) {
            logger.warn("The login page is being protected by the filter chain, but you don't appear to have" +
                    " anonymous authentication enabled. This is almost certainly an error.");
            return;
        }

        // Simulate an anonymous access with the supplied attributes.
        AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("key", anonPF.getPrincipal(),
                        anonPF.getAuthorities());
        try {
            fsi.getAccessDecisionManager().decide(token, loginRequest, attributes);
        } catch (AccessDeniedException e) {
            logger.warn("Anonymous access to the login page doesn't appear to be enabled. This is almost certainly " +
                    "an error. Please check your configuration allows unauthenticated access to the configured " +
                    "login page. (Simulated access was rejected: " + e + ")");
        }
    }

}
