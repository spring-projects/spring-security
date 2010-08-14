package org.springframework.security.config.http;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.config.ConstructorArgumentValues.ValueHolder;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Elements;
import org.springframework.security.config.authentication.AuthenticationManagerFactoryBean;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Sets up HTTP security: filter stack and protected URLs.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @since 2.0
 */
public class HttpSecurityBeanDefinitionParser implements BeanDefinitionParser {
    private static final Log logger = LogFactory.getLog(HttpSecurityBeanDefinitionParser.class);

    static final String ATT_PATH_PATTERN = "pattern";
    static final String ATT_HTTP_METHOD = "method";

    static final String ATT_FILTERS = "filters";
    static final String OPT_FILTERS_NONE = "none";

    static final String ATT_REQUIRES_CHANNEL = "requires-channel";

    private static final String ATT_REF = "ref";
    private static final String ATT_SECURED = "security";
    private static final String OPT_SECURITY_NONE = "none";

    public HttpSecurityBeanDefinitionParser() {
    }

    /**
     * The aim of this method is to build the list of filters which have been defined by the namespace elements
     * and attributes within the &lt;http&gt; configuration, along with any custom-filter's linked to user-defined
     * filter beans.
     * <p>
     * By the end of this method, the default <tt>FilterChainProxy</tt> bean should have been registered and will have
     * the map of filter chains defined, with the "universal" match pattern mapped to the list of beans which have been parsed here.
     */
    public BeanDefinition parse(Element element, ParserContext pc) {
        CompositeComponentDefinition compositeDef =
            new CompositeComponentDefinition(element.getTagName(), pc.extractSource(element));
        pc.pushContainingComponent(compositeDef);

        MatcherType matcherType = MatcherType.fromElement(element);
        ManagedMap<BeanDefinition, List<BeanMetadataElement>> filterChainMap = new ManagedMap<BeanDefinition, List<BeanMetadataElement>>();

        String filterChainPattern = element.getAttribute(ATT_PATH_PATTERN);

        BeanDefinition filterChainMatcher;

        if (StringUtils.hasText(filterChainPattern)) {
            filterChainMatcher = matcherType.createMatcher(filterChainPattern, null);
        } else {
            filterChainMatcher = new RootBeanDefinition(AnyRequestMatcher.class);
        }

        filterChainMap.put(filterChainMatcher, createFilterChain(element, pc, matcherType));

        registerFilterChainProxy(pc, filterChainMap, pc.extractSource(element));

        pc.popAndRegisterContainingComponent();
        return null;
    }

    List<BeanMetadataElement> createFilterChain(Element element, ParserContext pc, MatcherType matcherType) {
        String security = element.getAttribute(ATT_SECURED);

        if (StringUtils.hasText(security)) {
            if (!StringUtils.hasText(element.getAttribute(ATT_PATH_PATTERN))) {
                pc.getReaderContext().error("The '" + ATT_SECURED + "' attribute must be used in combination with" +
                        " the '" + ATT_PATH_PATTERN +"' attribute.", pc.extractSource(element));
            }

            for (int n=0; n < element.getChildNodes().getLength(); n ++) {
                if (element.getChildNodes().item(n) instanceof Element) {
                    pc.getReaderContext().error("If you are using <htt> to define an unsecured pattern, " +
                            "it cannot contain child elements.",  pc.extractSource(element));
                }
            }

            if (security.equals(OPT_SECURITY_NONE)) {
                return Collections.emptyList();
            }


        }

        final String portMapperName = createPortMapper(element, pc);

        ManagedList<BeanReference> authenticationProviders = new ManagedList<BeanReference>();
        BeanReference authenticationManager = createAuthenticationManager(element, pc, authenticationProviders);

        HttpConfigurationBuilder httpBldr = new HttpConfigurationBuilder(element, pc, matcherType,
                portMapperName, authenticationManager);

        AuthenticationConfigBuilder authBldr = new AuthenticationConfigBuilder(element, pc,
                httpBldr.getSessionCreationPolicy(), httpBldr.getRequestCache(), authenticationManager,
                httpBldr.getSessionStrategy());

        authenticationProviders.addAll(authBldr.getProviders());

        List<OrderDecorator> unorderedFilterChain = new ArrayList<OrderDecorator>();

        unorderedFilterChain.addAll(httpBldr.getFilters());
        unorderedFilterChain.addAll(authBldr.getFilters());
        unorderedFilterChain.addAll(buildCustomFilterList(element, pc));

        Collections.sort(unorderedFilterChain, new OrderComparator());
        checkFilterChainOrder(unorderedFilterChain, pc, pc.extractSource(element));

        List<BeanMetadataElement> filterChain = new ManagedList<BeanMetadataElement>();

        for (OrderDecorator od : unorderedFilterChain) {
            filterChain.add(od.bean);
        }

        return filterChain;
    }


    private String createPortMapper(Element elt, ParserContext pc) {
        // Register the portMapper. A default will always be created, even if no element exists.
        BeanDefinition portMapper = new PortMappingsBeanDefinitionParser().parse(
                DomUtils.getChildElementByTagName(elt, Elements.PORT_MAPPINGS), pc);
        String portMapperName = pc.getReaderContext().generateBeanName(portMapper);
        pc.registerBeanComponent(new BeanComponentDefinition(portMapper, portMapperName));

        return portMapperName;
    }

    /**
     * Creates the internal AuthenticationManager bean which uses the externally registered (global) one as
     * a parent.
     *
     * All the providers registered by this &lt;http&gt; block will be registered with the internal
     * authentication manager.
     */
    private BeanReference createAuthenticationManager(Element element, ParserContext pc,
            ManagedList<BeanReference> authenticationProviders) {
        BeanDefinitionBuilder authManager = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
        authManager.addPropertyValue("parent", new RootBeanDefinition(AuthenticationManagerFactoryBean.class));
        authManager.addPropertyValue("providers", authenticationProviders);
        RootBeanDefinition clearCredentials = new RootBeanDefinition(MethodInvokingFactoryBean.class);
        clearCredentials.getPropertyValues().addPropertyValue("targetObject", new RootBeanDefinition(AuthenticationManagerFactoryBean.class));
        clearCredentials.getPropertyValues().addPropertyValue("targetMethod", "isEraseCredentialsAfterAuthentication");
        authManager.addPropertyValue("eraseCredentialsAfterAuthentication", clearCredentials);

        authManager.getRawBeanDefinition().setSource(pc.extractSource(element));
        BeanDefinition authMgrBean = authManager.getBeanDefinition();
        String id = pc.getReaderContext().generateBeanName(authMgrBean);
        pc.registerBeanComponent(new BeanComponentDefinition(authMgrBean, id));

        return new RuntimeBeanReference(id);
    }

    private void checkFilterChainOrder(List<OrderDecorator> filters, ParserContext pc, Object source) {
        logger.info("Checking sorted filter chain: " + filters);

        for(int i=0; i < filters.size(); i++) {
            OrderDecorator filter = filters.get(i);

            if (i > 0) {
                OrderDecorator previous = filters.get(i-1);
                if (filter.getOrder() == previous.getOrder()) {
                    pc.getReaderContext().error("Filter beans '" + filter.bean + "' and '" +
                            previous.bean + "' have the same 'order' value. When using custom filters, " +
                                    "please make sure the positions do not conflict with default filters. " +
                                    "Alternatively you can disable the default filters by removing the corresponding " +
                                    "child elements from <http> and avoiding the use of <http auto-config='true'>.", source);
                }
            }
        }
    }

    List<OrderDecorator> buildCustomFilterList(Element element, ParserContext pc) {
        List<Element> customFilterElts = DomUtils.getChildElementsByTagName(element, Elements.CUSTOM_FILTER);
        List<OrderDecorator> customFilters = new ArrayList<OrderDecorator>();

        final String ATT_AFTER = "after";
        final String ATT_BEFORE = "before";
        final String ATT_POSITION = "position";

        for (Element elt: customFilterElts) {
            String after = elt.getAttribute(ATT_AFTER);
            String before = elt.getAttribute(ATT_BEFORE);
            String position = elt.getAttribute(ATT_POSITION);

            String ref = elt.getAttribute(ATT_REF);

            if (!StringUtils.hasText(ref)) {
                pc.getReaderContext().error("The '" + ATT_REF + "' attribute must be supplied", pc.extractSource(elt));
            }

            RuntimeBeanReference bean = new RuntimeBeanReference(ref);

            if(WebConfigUtils.countNonEmpty(new String[] {after, before, position}) != 1) {
                pc.getReaderContext().error("A single '" + ATT_AFTER + "', '" + ATT_BEFORE + "', or '" +
                        ATT_POSITION + "' attribute must be supplied", pc.extractSource(elt));
            }

            if (StringUtils.hasText(position)) {
                customFilters.add(new OrderDecorator(bean, SecurityFilters.valueOf(position)));
            } else if (StringUtils.hasText(after)) {
                SecurityFilters order = SecurityFilters.valueOf(after);
                if (order == SecurityFilters.LAST) {
                    customFilters.add(new OrderDecorator(bean, SecurityFilters.LAST));
                } else {
                    customFilters.add(new OrderDecorator(bean, order.getOrder() + 1));
                }
            } else if (StringUtils.hasText(before)) {
                SecurityFilters order = SecurityFilters.valueOf(before);
                if (order == SecurityFilters.FIRST) {
                    customFilters.add(new OrderDecorator(bean, SecurityFilters.FIRST));
                } else {
                    customFilters.add(new OrderDecorator(bean, order.getOrder() - 1));
                }
            }
        }

        return customFilters;
    }

    @SuppressWarnings("unchecked")
    private void registerFilterChainProxy(ParserContext pc, Map<BeanDefinition, List<BeanMetadataElement>> filterChainMap, Object source) {
        if (pc.getRegistry().containsBeanDefinition(BeanIds.FILTER_CHAIN_PROXY)) {
            // Already registered. Obtain the filter chain map and add the new entries to it
            // pc.getReaderContext().error("Duplicate <http> element detected", source);

            BeanDefinition fcp = pc.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
            Map existingFilterChainMap = (Map) fcp.getPropertyValues().getPropertyValue("filterChainMap").getValue();

            for (BeanDefinition matcherBean : filterChainMap.keySet()) {
                if (existingFilterChainMap.containsKey(matcherBean)) {
                    Map<Integer,ValueHolder> args = matcherBean.getConstructorArgumentValues().getIndexedArgumentValues();
                    pc.getReaderContext().error("The filter chain map already contains this request matcher ["
                            + args.get(0).getValue() + ", " +args.get(1).getValue() + "]", source);
                }
            }
            existingFilterChainMap.putAll(filterChainMap);
        } else {
            // Not already registered, so register it
            BeanDefinitionBuilder fcpBldr = BeanDefinitionBuilder.rootBeanDefinition(FilterChainProxy.class);
            fcpBldr.getRawBeanDefinition().setSource(source);
            fcpBldr.addPropertyValue("filterChainMap", filterChainMap);
            fcpBldr.addPropertyValue("filterChainValidator", new RootBeanDefinition(DefaultFilterChainValidator.class));
            BeanDefinition fcpBean = fcpBldr.getBeanDefinition();
            pc.registerBeanComponent(new BeanComponentDefinition(fcpBean, BeanIds.FILTER_CHAIN_PROXY));
            pc.getRegistry().registerAlias(BeanIds.FILTER_CHAIN_PROXY, BeanIds.SPRING_SECURITY_FILTER_CHAIN);
        }
    }

}

class OrderDecorator implements Ordered {
    final BeanMetadataElement bean;
    final int order;

    public OrderDecorator(BeanMetadataElement bean, SecurityFilters filterOrder) {
        this.bean = bean;
        this.order = filterOrder.getOrder();
    }

    public OrderDecorator(BeanMetadataElement bean, int order) {
        this.bean = bean;
        this.order = order;
    }

    public int getOrder() {
        return order;
    }

    public String toString() {
        return bean + ", order = " + order;
    }
}

