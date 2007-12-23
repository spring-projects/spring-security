package org.springframework.security.config;

import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.util.StringUtils;
import org.springframework.util.Assert;

import org.w3c.dom.Element;
import org.apache.directory.server.configuration.MutableServerStartupConfiguration;
import org.apache.directory.server.core.partition.impl.btree.MutableBTreePartitionConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.NamingException;
import java.util.HashSet;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapServerBeanDefinitionParser implements BeanDefinitionParser {
    private Log logger = LogFactory.getLog(getClass());

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
            contextSource = new RootBeanDefinition(DefaultSpringSecurityContextSource.class);
            contextSource.getConstructorArgumentValues().addIndexedArgumentValue(0, url);
        }

        String managerDn = elt.getAttribute(ATT_PRINCIPAL);
        String managerPassword = elt.getAttribute(ATT_PASSWORD);

        if (StringUtils.hasText(managerDn)) {
            Assert.hasText(managerPassword, "You must specify the " + ATT_PASSWORD +
                    " if you supply a " + managerDn);

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
     * @param element
     * @param parserContext
     *
     * @return the BeanDefinition for the ContextSource for the embedded server.
     *
     * @see ApacheDSContainer
     */
    private RootBeanDefinition createEmbeddedServer(Element element, ParserContext parserContext) {
        MutableServerStartupConfiguration configuration = new MutableServerStartupConfiguration();
        MutableBTreePartitionConfiguration partition = new MutableBTreePartitionConfiguration();

        partition.setName("springsecurity");

        DirContextAdapter rootContext = new DirContextAdapter();
        rootContext.setAttributeValues("objectClass", new String[] {"top", "domain", "extensibleObject"});
        rootContext.setAttributeValue("dc", "springsecurity");

        partition.setContextEntry(rootContext.getAttributes());

        String suffix = element.getAttribute(ATT_ROOT_SUFFIX);

        if (!StringUtils.hasText(suffix)) {
            suffix = OPT_DEFAULT_ROOT_SUFFIX;
        }

        try {
            partition.setSuffix(suffix);
        } catch (NamingException e) {
            parserContext.getReaderContext().error("Failed to set root name suffix to " + suffix, element, e);
        }

        HashSet partitions = new HashSet(1);
        partitions.add(partition);

        String port = element.getAttribute(ATT_PORT);

        if (!StringUtils.hasText(port)) {
            port = OPT_DEFAULT_PORT;
        }

        configuration.setLdapPort(Integer.parseInt(port));

        // We shut down the server ourself when the app context is closed so we don't need
        // the extra shutdown hook from apache DS itself.
        configuration.setShutdownHookEnabled(false);
        configuration.setExitVmOnShutdown(false);
        configuration.setContextPartitionConfigurations(partitions);

        String url = "ldap://127.0.0.1:" + port + "/" + suffix;

        RootBeanDefinition contextSource = new RootBeanDefinition(DefaultSpringSecurityContextSource.class);
        contextSource.getConstructorArgumentValues().addIndexedArgumentValue(0, url);
        contextSource.getPropertyValues().addPropertyValue("userDn", "uid=admin,ou=system");
        contextSource.getPropertyValues().addPropertyValue("password", "secret");

        RootBeanDefinition apacheContainer = new RootBeanDefinition(ApacheDSContainer.class);
        apacheContainer.getConstructorArgumentValues().addGenericArgumentValue(configuration);
        apacheContainer.getConstructorArgumentValues().addGenericArgumentValue(contextSource);

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

        return contextSource;
    }
}
