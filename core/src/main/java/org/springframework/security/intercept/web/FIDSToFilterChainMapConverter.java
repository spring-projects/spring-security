package org.springframework.security.intercept.web;

import org.springframework.context.ApplicationContext;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.util.FilterChainProxy;

import javax.servlet.Filter;
import java.util.*;

/**
 * Used internally to provide backward compatibility for configuration of FilterChainProxy using a
 * FilterInvocationDefinitionSource. This is deprecated in favour of namespace-based configuration.
 *
 * This class will convert a FilterInvocationDefinitionSource into a suitable Map, provided it is one of the
 * recognised implementations (ant path or regular expression). The order of the mappings will be
 * preserved in the Map.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class FIDSToFilterChainMapConverter {

    private LinkedHashMap filterChainMap = new LinkedHashMap();

    public FIDSToFilterChainMapConverter(FilterInvocationDefinitionSource fids, ApplicationContext appContext) {

        List requestMap;

        // TODO: Check if this is necessary. Retained from refactoring of FilterChainProxy 
        if (fids.getConfigAttributeDefinitions() == null) {
            throw new IllegalArgumentException("FilterChainProxy requires the FilterInvocationDefinitionSource to " +
                    "return a non-null response to getConfigAttributeDefinitions()");
        }

        if (fids instanceof PathBasedFilterInvocationDefinitionMap) {
            requestMap = ((PathBasedFilterInvocationDefinitionMap)fids).getRequestMap();
        } else if (fids instanceof RegExpBasedFilterInvocationDefinitionMap) {
            requestMap = ((RegExpBasedFilterInvocationDefinitionMap)fids).getRequestMap();
        } else {
            throw new IllegalArgumentException("Can't handle FilterInvocationDefinitionSource type " + fids.getClass());
        }

        Iterator entries = requestMap.iterator();

        while (entries.hasNext()) {
            Object entry = entries.next();
            String path;
            ConfigAttributeDefinition configAttributeDefinition;

            if (entry instanceof PathBasedFilterInvocationDefinitionMap.EntryHolder) {
                path = ((PathBasedFilterInvocationDefinitionMap.EntryHolder)entry).getAntPath();
                configAttributeDefinition = ((PathBasedFilterInvocationDefinitionMap.EntryHolder)entry).getConfigAttributeDefinition();
            } else {
                path = ((RegExpBasedFilterInvocationDefinitionMap.EntryHolder)entry).getCompiledPattern().pattern();
                configAttributeDefinition = ((RegExpBasedFilterInvocationDefinitionMap.EntryHolder)entry).getConfigAttributeDefinition();
            }

            List filters = new ArrayList();

            Iterator attributes = configAttributeDefinition.getConfigAttributes();

            while (attributes.hasNext()) {
                ConfigAttribute attr = (ConfigAttribute) attributes.next();
                String filterName = attr.getAttribute();

                if (filterName == null) {
                    throw new IllegalArgumentException("Configuration attribute: '" + attr
                        + "' returned null to the getAttribute() method, which is invalid when used with FilterChainProxy");
                }

                if (!filterName.equals(FilterChainProxy.TOKEN_NONE)) {
                    filters.add(appContext.getBean(filterName, Filter.class));
                }
            }

            filterChainMap.put(path, filters);
        }
    }

    public Map getFilterChainMap() {
        return filterChainMap;
    }
}
