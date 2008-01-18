package org.springframework.security.intercept.web;

import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.util.FilterChainProxy;

import javax.servlet.Filter;
import java.util.*;
import java.util.regex.Pattern;

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

    public FIDSToFilterChainMapConverter(FilterInvocationDefinitionSource source, ApplicationContext appContext) {
        // TODO: Check if this is necessary. Retained from refactoring of FilterChainProxy
        Assert.notNull(source.getConfigAttributeDefinitions(), "FilterChainProxy requires the " +
                "FilterInvocationDefinitionSource to return a non-null response to getConfigAttributeDefinitions()");
        Assert.isTrue(
            source instanceof PathBasedFilterInvocationDefinitionMap ||
            source instanceof RegExpBasedFilterInvocationDefinitionMap,
                "Can't handle FilterInvocationDefinitionSource type " + source.getClass());
        

        AbstractFilterInvocationDefinitionSource fids = (AbstractFilterInvocationDefinitionSource)source;
        Map requestMap = fids.getRequestMap();
        Iterator paths = requestMap.keySet().iterator();

        while (paths.hasNext()) {
            Object entry = paths.next();
            String path = entry instanceof Pattern ? ((Pattern)entry).pattern() : (String)entry;
            ConfigAttributeDefinition configAttributeDefinition = (ConfigAttributeDefinition) requestMap.get(entry);

            List filters = new ArrayList();
            Iterator attributes = configAttributeDefinition.getConfigAttributes();

            while (attributes.hasNext()) {
                ConfigAttribute attr = (ConfigAttribute) attributes.next();
                String filterName = attr.getAttribute();

                Assert.notNull(filterName, "Configuration attribute: '" + attr + "' returned null to the getAttribute() " +
                        "method, which is invalid when used with FilterChainProxy");

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
