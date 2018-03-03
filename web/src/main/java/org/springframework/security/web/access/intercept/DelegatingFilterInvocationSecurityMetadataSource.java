package org.springframework.security.web.access.intercept;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.*;

public class DelegatingFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    FilterInvocationSecurityMetadataSource securityMetadataSource;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        return securityMetadataSource.getAttributes(object);
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return securityMetadataSource.getAllConfigAttributes();
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return securityMetadataSource.supports(clazz );
    }

    public DelegatingFilterInvocationSecurityMetadataSource(Map<String, String> urlMap ) {
        loadSecurityMetadataSourceFromUrlMap(urlMap);
    }

    /**
     * @param urlMap store url<--> express
     */
    public synchronized void loadSecurityMetadataSourceFromUrlMap(Map<String, String> urlMap) {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap  = new LinkedHashMap(urlMap.size());
        for (Map.Entry<String, String> entry : urlMap
                .entrySet()) {
            RequestMatcher requestMatcher = new AntPathRequestMatcher(entry.getKey());
            Set<String> set = StringUtils.commaDelimitedListToSet(entry.getValue());
            Collection<ConfigAttribute> configAttributes = new LinkedHashSet<>(set.size());
            for (String str : set) {
                configAttributes.add(new SecurityConfig(str));
            }
            requestMap.put(requestMatcher, configAttributes);

        }
        FilterInvocationSecurityMetadataSource metadataSource =
                new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, new DefaultWebSecurityExpressionHandler());
        this.securityMetadataSource = metadataSource;
    }

    public DelegatingFilterInvocationSecurityMetadataSource(Set<String> urlSet ) {
        Map<String, String> urlMap  = new LinkedHashMap(urlSet.size());
         for (String resource : urlSet) {
             urlMap.put(resource,resource);
         }
         loadSecurityMetadataSourceFromUrlMap(urlMap);
    }
}
