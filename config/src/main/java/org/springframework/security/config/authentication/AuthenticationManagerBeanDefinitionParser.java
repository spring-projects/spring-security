package org.springframework.security.config.authentication;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Registers an alias name for the default ProviderManager used by the namespace
 * configuration, allowing users to reference it in their beans and clearly see where the name is
 * coming from. Also allows the ConcurrentSessionController to be set on the ProviderManager.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationManagerBeanDefinitionParser implements BeanDefinitionParser {
    private static final String ATT_SESSION_CONTROLLER_REF = "session-controller-ref";
    private static final String ATT_ALIAS = "alias";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        ConfigUtils.registerProviderManagerIfNecessary(parserContext, element);

        String alias = element.getAttribute(ATT_ALIAS);

        if (!StringUtils.hasText(alias)) {
            parserContext.getReaderContext().error(ATT_ALIAS + " is required.", element );
        }

        String sessionControllerRef = element.getAttribute(ATT_SESSION_CONTROLLER_REF);

        if (StringUtils.hasText(sessionControllerRef)) {
            parserContext.getReaderContext().warning(ATT_SESSION_CONTROLLER_REF + " is not supported in Spring Security " +
                    " 3.0 and will be ignored. Use the attribute on the <concurrent-session-control> element instead.",
                    parserContext.extractSource(element));
        }

        parserContext.getRegistry().registerAlias(BeanIds.AUTHENTICATION_MANAGER, alias);
        parserContext.getReaderContext().fireAliasRegistered(BeanIds.AUTHENTICATION_MANAGER, alias, parserContext.extractSource(element));

        return null;
    }
}
