package org.springframework.security.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.NamespaceHandler;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.config.authentication.AuthenticationProviderBeanDefinitionParser;
import org.springframework.security.config.authentication.JdbcUserServiceBeanDefinitionParser;
import org.springframework.security.config.authentication.UserServiceBeanDefinitionParser;
import org.springframework.security.config.http.FilterChainMapBeanDefinitionDecorator;
import org.springframework.security.config.http.FilterInvocationSecurityMetadataSourceParser;
import org.springframework.security.config.http.HttpSecurityBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapProviderBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapServerBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapUserServiceBeanDefinitionParser;
import org.springframework.security.config.method.GlobalMethodSecurityBeanDefinitionParser;
import org.springframework.security.config.method.InterceptMethodsBeanDefinitionDecorator;
import org.springframework.security.config.method.MethodSecurityMetadataSourceBeanDefinitionParser;
import org.springframework.util.ClassUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Parses elements from the "security" namespace (http://www.springframework.org/schema/security).
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @since 2.0
 */
public final class SecurityNamespaceHandler implements NamespaceHandler {
    private final Map<String, BeanDefinitionParser> parsers = new HashMap<String, BeanDefinitionParser>();
    private final BeanDefinitionDecorator interceptMethodsBDD = new InterceptMethodsBeanDefinitionDecorator();
    private BeanDefinitionDecorator filterChainMapBDD;

    public BeanDefinition parse(Element element, ParserContext pc) {
        if (!namespaceMatchesVersion(element)) {
            pc.getReaderContext().fatal("You cannot use a spring-security-2.0.xsd or spring-security-3.0.xsd schema " +
                    "with Spring Security 3.1. Please update your schema declarations to the 3.1 schema.", element);
        }
        String name = pc.getDelegate().getLocalName(element);
        BeanDefinitionParser parser = parsers.get(name);

        if (parser == null) {
            // SEC-1455. Load parsers when required, not just on init().
            loadParsers();
        }

        if (parser == null) {
            if (Elements.HTTP.equals(name) || Elements.FILTER_SECURITY_METADATA_SOURCE.equals(name) ||
                    Elements.FILTER_CHAIN_MAP.equals(name)) {
                reportMissingWebClasses(name, pc, element);
            } else {
                reportUnsupportedNodeType(name, pc, element);
            }

            return null;
        }

        return parser.parse(element, pc);
    }

    public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder definition, ParserContext pc) {
        String name = pc.getDelegate().getLocalName(node);

        // We only handle elements
        if (node instanceof Element) {
            if (Elements.INTERCEPT_METHODS.equals(name)) {
                return interceptMethodsBDD.decorate(node, definition, pc);
            }

            if (Elements.FILTER_CHAIN_MAP.equals(name)) {
                if (filterChainMapBDD == null) {
                    loadParsers();
                }
                if (filterChainMapBDD == null) {
                    reportMissingWebClasses(name, pc, node);
                }
                return filterChainMapBDD.decorate(node, definition, pc);
            }
        }

        reportUnsupportedNodeType(name, pc, node);

        return null;
    }

    private void reportUnsupportedNodeType(String name, ParserContext pc, Node node) {
        pc.getReaderContext().fatal("Security namespace does not support decoration of " +
                (node instanceof Element ? "element" : "attribute") + " [" + name + "]", node);
    }

    private void reportMissingWebClasses(String nodeName, ParserContext pc, Node node) {
        pc.getReaderContext().fatal("spring-security-web classes are not available. " +
                "You need these to use <" + nodeName + ">", node);
    }

    public void init() {
        loadParsers();
    }

    @SuppressWarnings("deprecation")
    private void loadParsers() {
        // Parsers
        parsers.put(Elements.LDAP_PROVIDER, new LdapProviderBeanDefinitionParser());
        parsers.put(Elements.LDAP_SERVER, new LdapServerBeanDefinitionParser());
        parsers.put(Elements.LDAP_USER_SERVICE, new LdapUserServiceBeanDefinitionParser());
        parsers.put(Elements.USER_SERVICE, new UserServiceBeanDefinitionParser());
        parsers.put(Elements.JDBC_USER_SERVICE, new JdbcUserServiceBeanDefinitionParser());
        parsers.put(Elements.AUTHENTICATION_PROVIDER, new AuthenticationProviderBeanDefinitionParser());
        parsers.put(Elements.GLOBAL_METHOD_SECURITY, new GlobalMethodSecurityBeanDefinitionParser());
        parsers.put(Elements.AUTHENTICATION_MANAGER, new AuthenticationManagerBeanDefinitionParser());
        parsers.put(Elements.METHOD_SECURITY_METADATA_SOURCE, new MethodSecurityMetadataSourceBeanDefinitionParser());
        parsers.put(Elements.DEBUG, new DebugBeanDefinitionParser());

        // Only load the web-namespace parsers if the web classes are available
        if (ClassUtils.isPresent("org.springframework.security.web.FilterChainProxy", getClass().getClassLoader())) {
            parsers.put(Elements.HTTP, new HttpSecurityBeanDefinitionParser());
            parsers.put(Elements.FILTER_INVOCATION_DEFINITION_SOURCE, new FilterInvocationSecurityMetadataSourceParser());
            parsers.put(Elements.FILTER_SECURITY_METADATA_SOURCE, new FilterInvocationSecurityMetadataSourceParser());
            filterChainMapBDD = new FilterChainMapBeanDefinitionDecorator();
        }
    }

    /**
     * Check that the schema location declared in the source file being parsed matches the Spring Security version.
     * The old 2.0 schema is not compatible with the 3.1 parser, so it is an error to explicitly use
     * 2.0.
     * <p>
     * There are also differences between 3.0 and 3.1 which are sufficient that we report using 3.0 as an error too.
     * It might be an error to declare spring-security.xsd as an alias, but you are only going to find that out
     * when one of the sub parsers breaks.
     *
     * @param element the element that is to be parsed next
     * @return true if we find a schema declaration that matches
     */
    private boolean namespaceMatchesVersion(Element element) {
        return matchesVersionInternal(element) && matchesVersionInternal(element.getOwnerDocument().getDocumentElement());
    }

    private boolean matchesVersionInternal(Element element) {
        String schemaLocation = element.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "schemaLocation");
        return schemaLocation.matches("(?m).*spring-security-3\\.1.*.xsd.*")
                 || schemaLocation.matches("(?m).*spring-security.xsd.*")
                 || !schemaLocation.matches("(?m).*spring-security.*");
    }

}
