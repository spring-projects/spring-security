package org.springframework.security.config.http;

import java.util.Collection;
import java.util.List;

import javax.servlet.Filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.AnyRequestMatcher;

public class DefaultFilterChainValidator implements FilterChainProxy.FilterChainValidator {
    private Log logger = LogFactory.getLog(getClass());

    public void validate(FilterChainProxy fcp) {
        for(List<Filter> filters : fcp.getFilterChainMap().values()) {
            checkFilterStack(filters);
        }

        checkLoginPageIsntProtected(fcp);
    }

    private Object getFilter(Class<?> type, List<Filter> filters) {

        for (Filter f : filters) {
            if (type.isAssignableFrom(f.getClass())) {
                return f;
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
        List<Filter> defaultFilters = fcp.getFilterChainMap().get(new AnyRequestMatcher());
        ExceptionTranslationFilter etf = (ExceptionTranslationFilter)getFilter(ExceptionTranslationFilter.class, defaultFilters);

        if (etf.getAuthenticationEntryPoint() instanceof LoginUrlAuthenticationEntryPoint) {
            String loginPage =
                ((LoginUrlAuthenticationEntryPoint)etf.getAuthenticationEntryPoint()).getLoginFormUrl();
            FilterInvocation loginRequest = new FilterInvocation(loginPage, "POST");
            List<Filter> filters = fcp.getFilters(loginPage);
            logger.info("Checking whether login URL '" + loginPage + "' is accessible with your configuration");

            if (filters == null || filters.isEmpty()) {
                logger.debug("Filter chain is empty for the login page");
                return;
            }

            if (getFilter(DefaultLoginPageGeneratingFilter.class, filters) != null) {
                logger.debug("Default generated login page is in use");
                return;
            }

            FilterSecurityInterceptor fsi = (FilterSecurityInterceptor) getFilter(FilterSecurityInterceptor.class, filters);
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

            AnonymousAuthenticationFilter anonPF = (AnonymousAuthenticationFilter) getFilter(AnonymousAuthenticationFilter.class, filters);
            if (anonPF == null) {
                logger.warn("The login page is being protected by the filter chain, but you don't appear to have" +
                        " anonymous authentication enabled. This is almost certainly an error.");
                return;
            }

            // Simulate an anonymous access with the supplied attributes.
            AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("key", anonPF.getUserAttribute().getPassword(),
                            anonPF.getUserAttribute().getAuthorities());
            try {
                fsi.getAccessDecisionManager().decide(token, new Object(), attributes);
            } catch (Exception e) {
                logger.warn("Anonymous access to the login page doesn't appear to be enabled. This is almost certainly " +
                        "an error. Please check your configuration allows unauthenticated access to the configured " +
                        "login page. (Simulated access was rejected: " + e + ")");
            }
        }
    }
}
