package org.springframework.security.config.authentication;

import java.util.List;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.NamespaceHandlerResolver;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Registers the central ProviderManager used by the namespace configuration, and allows the configuration of an
 * alias, allowing users to reference it in their beans and clearly see where the name is
 * coming from.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationManagerBeanDefinitionParser implements BeanDefinitionParser {
    private static final String ATT_ALIAS = "alias";
    private static final String ATT_REF = "ref";

    public BeanDefinition parse(Element element, ParserContext pc) {
        Assert.state(!pc.getRegistry().containsBeanDefinition(BeanIds.AUTHENTICATION_MANAGER),
                "AuthenticationManager has already been registered!");
        pc.pushContainingComponent(new CompositeComponentDefinition(element.getTagName(), pc.extractSource(element)));

        BeanDefinitionBuilder providerManagerBldr = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);

        String alias = element.getAttribute(ATT_ALIAS);

        checkForDeprecatedSessionControllerRef(element, pc);
        List<BeanMetadataElement> providers = new ManagedList<BeanMetadataElement>();
        NamespaceHandlerResolver resolver = pc.getReaderContext().getNamespaceHandlerResolver();

        NodeList children = element.getChildNodes();

        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node instanceof Element) {
                Element providerElt = (Element)node;
                if (StringUtils.hasText(providerElt.getAttribute(ATT_REF))) {
                    providers.add(new RuntimeBeanReference(providerElt.getAttribute(ATT_REF)));
                } else {
                    BeanDefinition provider = resolver.resolve(providerElt.getNamespaceURI()).parse(providerElt, pc);
                    Assert.notNull(provider, "Parser for " + providerElt.getNodeName() + " returned a null bean definition");
                    providers.add(provider);
                }
            }
        }

        if (providers.isEmpty()) {
            providers.add(new RootBeanDefinition(NullAuthenticationProvider.class));
        }

        providerManagerBldr.addPropertyValue("providers", providers);

        BeanDefinition authManager = providerManagerBldr.getBeanDefinition();
        pc.getRegistry().registerBeanDefinition(BeanIds.AUTHENTICATION_MANAGER, authManager);
        pc.registerBeanComponent(new BeanComponentDefinition(authManager, BeanIds.AUTHENTICATION_MANAGER));

        if (StringUtils.hasText(alias)) {
            pc.getRegistry().registerAlias(BeanIds.AUTHENTICATION_MANAGER, alias);
            pc.getReaderContext().fireAliasRegistered(BeanIds.AUTHENTICATION_MANAGER, alias, pc.extractSource(element));
        }

        pc.popAndRegisterContainingComponent();

        return null;
    }

    private void checkForDeprecatedSessionControllerRef(Element element, ParserContext pc) {
        final String ATT_SESSION_CONTROLLER_REF = "session-controller-ref";

        if (StringUtils.hasText(element.getAttribute(ATT_SESSION_CONTROLLER_REF))) {
            pc.getReaderContext().warning(ATT_SESSION_CONTROLLER_REF + " is not supported in Spring Security " +
                    " 3.0 and will be ignored. Use the attribute on the <concurrent-session-control> element instead.",
                    pc.extractSource(element));
        }
    }

    /**
     * Provider which doesn't provide any service. Only used to prevent a configuration exception if the provider list
     * is empty (usually because a child ProviderManager from the &lt;http&gt; namespace, such as OpenID, is expected
     * to handle the request).
     */
    public static final class NullAuthenticationProvider implements AuthenticationProvider {
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            return null;
        }

        public boolean supports(Class<? extends Object> authentication) {
            return false;
        }
    }
}
