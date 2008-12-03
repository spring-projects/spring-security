package org.springframework.security.config;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedSet;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapServerBeanDefinitionParser implements BeanDefinitionParser {
    private static final String CONTEXT_SOURCE_CLASS="org.springframework.security.ldap.DefaultSpringSecurityContextSource";

    private final Log logger = LogFactory.getLog(getClass());

    /** Defines the Url of the ldap server to use. If not specified, an embedded apache DS instance will be created */
    private static final String ATT_URL = "url";

    private static final String ATT_PRINCIPAL = "manager-dn";
    private static final String ATT_PASSWORD = "manager-password";

    // Properties which apply to embedded server only - when no Url is set

    /** sets the configuration suffix (default is "dc=springframework,dc=org"). */
    public static final String ATT_ROOT_SUFFIX = "root";
    private static final String OPT_DEFAULT_ROOT_SUFFIX = "dc=springframework,dc=org";
    /**
     * Optionally defines an ldif resource to be loaded. Otherwise an attempt will be made to load all ldif files
     * found on the classpath.
     */
    public static final String ATT_LDIF_FILE = "ldif";
    private static final String OPT_DEFAULT_LDIF_FILE = "classpath*:*.ldif";

    /** Defines the port the LDAP_PROVIDER server should run on */
    public static final String ATT_PORT = "port";
    public static final String OPT_DEFAULT_PORT = "33389";


    public BeanDefinition parse(Element elt, ParserContext parserContext) {
        String url = elt.getAttribute(ATT_URL);

        RootBeanDefinition contextSource;

        if (!StringUtils.hasText(url)) {
            contextSource = createEmbeddedServer(elt, parserContext);
        } else {
            contextSource = new RootBeanDefinition();
            contextSource.setBeanClassName(CONTEXT_SOURCE_CLASS);
            contextSource.getConstructorArgumentValues().addIndexedArgumentValue(0, url);
        }

        contextSource.setSource(parserContext.extractSource(elt));

        String managerDn = elt.getAttribute(ATT_PRINCIPAL);
        String managerPassword = elt.getAttribute(ATT_PASSWORD);

        if (StringUtils.hasText(managerDn)) {
            if(!StringUtils.hasText(managerPassword)) {
                parserContext.getReaderContext().error("You must specify the " + ATT_PASSWORD +
                        " if you supply a " + managerDn, elt);
            }

            contextSource.getPropertyValues().addPropertyValue("userDn", managerDn);
            contextSource.getPropertyValues().addPropertyValue("password", managerPassword);
        }

        String id = elt.getAttribute(AbstractBeanDefinitionParser.ID_ATTRIBUTE);

        String contextSourceId = StringUtils.hasText(id) ? id : BeanIds.CONTEXT_SOURCE;

        parserContext.getRegistry().registerBeanDefinition(contextSourceId, contextSource);

        return null;
    }

    /**
     * Will be called if no url attribute is supplied.
     *
     * Registers beans to create an embedded apache directory server.
     *
     * @return the BeanDefinition for the ContextSource for the embedded server.
     *
     * @see ApacheDSContainer
     */
    @SuppressWarnings("unchecked")
    private RootBeanDefinition createEmbeddedServer(Element element, ParserContext parserContext) {
        Object source = parserContext.extractSource(element);
        BeanDefinitionBuilder configuration =
            BeanDefinitionBuilder.rootBeanDefinition("org.apache.directory.server.configuration.MutableServerStartupConfiguration");
        BeanDefinitionBuilder partition =
            BeanDefinitionBuilder.rootBeanDefinition("org.apache.directory.server.core.partition.impl.btree.MutableBTreePartitionConfiguration");
        configuration.getRawBeanDefinition().setSource(source);
        partition.getRawBeanDefinition().setSource(source);

        Attributes rootAttributes = new BasicAttributes("dc", "springsecurity");
        Attribute a = new BasicAttribute("objectClass");
        a.add("top");
        a.add("domain");
        a.add("extensibleObject");
        rootAttributes.put(a);

        partition.addPropertyValue("name", "springsecurity");
        partition.addPropertyValue("contextEntry", rootAttributes);

        String suffix = element.getAttribute(ATT_ROOT_SUFFIX);

        if (!StringUtils.hasText(suffix)) {
            suffix = OPT_DEFAULT_ROOT_SUFFIX;
        }

        partition.addPropertyValue("suffix", suffix);

        ManagedSet partitions = new ManagedSet(1);
        partitions.add(partition.getBeanDefinition());

        String port = element.getAttribute(ATT_PORT);

        if (!StringUtils.hasText(port)) {
            port = OPT_DEFAULT_PORT;
        }

        configuration.addPropertyValue("ldapPort", port);

        // We shut down the server ourself when the app context is closed so we don't need
        // the extra shutdown hook from apache DS itself.
        configuration.addPropertyValue("shutdownHookEnabled", Boolean.FALSE);
        configuration.addPropertyValue("exitVmOnShutdown", Boolean.FALSE);
        configuration.addPropertyValue("contextPartitionConfigurations", partitions);

        String url = "ldap://127.0.0.1:" + port + "/" + suffix;

        BeanDefinitionBuilder contextSource = BeanDefinitionBuilder.rootBeanDefinition(CONTEXT_SOURCE_CLASS);
        contextSource.addConstructorArgValue(url);
        contextSource.addPropertyValue("userDn", "uid=admin,ou=system");
        contextSource.addPropertyValue("password", "secret");

        RootBeanDefinition apacheContainer = new RootBeanDefinition("org.springframework.security.config.ApacheDSContainer", null, null);
        apacheContainer.setSource(source);
        apacheContainer.getConstructorArgumentValues().addGenericArgumentValue(configuration.getBeanDefinition());
        apacheContainer.getConstructorArgumentValues().addGenericArgumentValue(contextSource.getBeanDefinition());

        String ldifs = element.getAttribute(ATT_LDIF_FILE);
        if (!StringUtils.hasText(ldifs)) {
            ldifs = OPT_DEFAULT_LDIF_FILE;
        }

        apacheContainer.getConstructorArgumentValues().addGenericArgumentValue(ldifs);

        logger.info("Embedded LDAP server bean created for URL: " + url);

        if (parserContext.getRegistry().containsBeanDefinition(BeanIds.EMBEDDED_APACHE_DS)) {
            parserContext.getReaderContext().error("Only one embedded server bean is allowed per application context",
                    element);
        }

        parserContext.getRegistry().registerBeanDefinition(BeanIds.EMBEDDED_APACHE_DS, apacheContainer);

        return (RootBeanDefinition) contextSource.getBeanDefinition();
    }
}
