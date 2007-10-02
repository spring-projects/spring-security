package org.springframework.security.config;

import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.util.StringUtils;
import org.springframework.security.ldap.DefaultInitialDirContextFactory;
import org.springframework.security.providers.ldap.LdapAuthenticationProvider;
import org.springframework.security.providers.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.providers.ldap.authenticator.BindAuthenticator;
import org.springframework.ldap.core.DirContextAdapter;
import org.w3c.dom.Element;
import org.apache.directory.server.configuration.MutableServerStartupConfiguration;
import org.apache.directory.server.core.partition.impl.btree.MutableBTreePartitionConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.NamingException;
import java.util.HashSet;

/**
 * Experimental "security:ldap" namespace configuration.
 *
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class LdapBeanDefinitionParser extends AbstractBeanDefinitionParser {
    private Log logger = LogFactory.getLog(getClass());

    /** Defines the Url of the ldap server to use. If not specified, an embedded apache DS instance will be created */
    private static final String URL_ATTRIBUTE = "url";
    private static final String AUTH_TYPE_ATTRIBUTE = "auth";
    // TODO: Setting login/passwords for non embedded server. 
    private static final String PRINCIPAL_ATTRIBUTE = "managerDn";
    private static final String PASSWORD_ATTRIBUTE = "managerPassword";

    // Properties which apply to embedded server only - when no Url is set

    /** sets the configuration suffix (default is "dc=springframework,dc=org"). */
    public static final String ROOT_SUFFIX_ATTRIBUTE = "root";

    /**
     * Optionally defines an ldif resource to be loaded. Otherwise an attempt will be made to load all ldif files
     * found on the classpath.
     */
    public static final String LDIF_FILE_ATTRIBUTE = "ldif";

    // Defaults
    private static final String DEFAULT_ROOT_SUFFIX = "dc=springframework,dc=org";

    private static final String DEFAULT_PROVIDER_BEAN_ID = "_ldapProvider";

    private static final String DEFAULT_DN_PATTERN = "uid={0},ou=people";

    private static final String DEFAULT_GROUP_CONTEXT = "ou=groups";


    protected AbstractBeanDefinition parseInternal(Element elt, ParserContext parserContext) {
        String url = elt.getAttribute(URL_ATTRIBUTE);

        RootBeanDefinition initialDirContextFactory;

        if (!StringUtils.hasText(url)) {
            initialDirContextFactory = createEmbeddedServer(elt, parserContext);
        } else {
            initialDirContextFactory = new RootBeanDefinition(DefaultInitialDirContextFactory.class);
            initialDirContextFactory.getConstructorArgumentValues().addIndexedArgumentValue(0, url);
        }

        // TODO: Make these default values for 2.0
        initialDirContextFactory.getPropertyValues().addPropertyValue("useLdapContext", Boolean.TRUE);
        initialDirContextFactory.getPropertyValues().addPropertyValue("dirObjectFactory", "org.springframework.ldap.core.support.DefaultDirObjectFactory");

        String id = elt.getAttribute(ID_ATTRIBUTE);
        String contextSourceId = "contextSource";

        if (StringUtils.hasText(id)) {
            contextSourceId = id + "." + contextSourceId;
        }

        if (parserContext.getRegistry().containsBeanDefinition(contextSourceId)) {
            logger.warn("Bean already exists with Id '" + contextSourceId + "'");
        }

        parserContext.getRegistry().registerBeanDefinition(contextSourceId, initialDirContextFactory);

        RootBeanDefinition bindAuthenticator = new RootBeanDefinition(BindAuthenticator.class);
        bindAuthenticator.getConstructorArgumentValues().addGenericArgumentValue(initialDirContextFactory);
        bindAuthenticator.getPropertyValues().addPropertyValue("userDnPatterns", new String[] {DEFAULT_DN_PATTERN});
        RootBeanDefinition authoritiesPopulator = new RootBeanDefinition(DefaultLdapAuthoritiesPopulator.class);
        authoritiesPopulator.getConstructorArgumentValues().addGenericArgumentValue(initialDirContextFactory);
        authoritiesPopulator.getConstructorArgumentValues().addGenericArgumentValue(DEFAULT_GROUP_CONTEXT);

        RootBeanDefinition ldapProvider = new RootBeanDefinition(LdapAuthenticationProvider.class);
        ldapProvider.getConstructorArgumentValues().addGenericArgumentValue(bindAuthenticator);
        ldapProvider.getConstructorArgumentValues().addGenericArgumentValue(authoritiesPopulator);

        return ldapProvider;
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
     * @see ApacheDSStartStopBean
     */
    private RootBeanDefinition createEmbeddedServer(Element element, ParserContext parserContext) {
        MutableServerStartupConfiguration configuration = new MutableServerStartupConfiguration();
        MutableBTreePartitionConfiguration partition = new MutableBTreePartitionConfiguration();

        partition.setName("springsecurity");

        DirContextAdapter rootContext = new DirContextAdapter();
        rootContext.setAttributeValues("objectClass", new String[] {"top", "domain", "extensibleObject"});
        rootContext.setAttributeValue("dc", "springsecurity");

        partition.setContextEntry(rootContext.getAttributes());

        String suffix = element.getAttribute(ROOT_SUFFIX_ATTRIBUTE);

        if (!StringUtils.hasText(suffix)) {
            suffix = DEFAULT_ROOT_SUFFIX;
        }

        try {
            partition.setSuffix(suffix);
        } catch (NamingException e) {
            // TODO: What exception should we be throwing here ?

            logger.error("Failed to set root name suffix to " + suffix, e);
        }

        HashSet partitions = new HashSet(1);
        partitions.add(partition);

        //TODO: Allow port configuration
        configuration.setLdapPort(3389);
        // We shut down the server ourself when the app context is closed so we don't need
        // the extra shutdown hook from apache DS itself.
        configuration.setShutdownHookEnabled(false);
        configuration.setExitVmOnShutdown(false);
        configuration.setContextPartitionConfigurations(partitions);

        RootBeanDefinition initialDirContextFactory = new RootBeanDefinition(DefaultInitialDirContextFactory.class);
        initialDirContextFactory.getConstructorArgumentValues().addIndexedArgumentValue(0, "ldap://127.0.0.1:3389/" + suffix);

        initialDirContextFactory.getPropertyValues().addPropertyValue("managerDn", "uid=admin,ou=system");
        initialDirContextFactory.getPropertyValues().addPropertyValue("managerPassword", "secret");

        RootBeanDefinition apacheDSStartStop = new RootBeanDefinition(ApacheDSStartStopBean.class);
        apacheDSStartStop.getConstructorArgumentValues().addGenericArgumentValue(configuration);
        apacheDSStartStop.getConstructorArgumentValues().addGenericArgumentValue(initialDirContextFactory);

        if (parserContext.getRegistry().containsBeanDefinition("_apacheDSStartStopBean")) {
            //TODO: Appropriate exception
            throw new IllegalArgumentException("Only one embedded server bean is allowed per application context");
        }

        parserContext.getRegistry().registerBeanDefinition("_apacheDSStartStopBean", apacheDSStartStop);

        return initialDirContextFactory;
    }


    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) throws BeanDefinitionStoreException {
        String id = super.resolveId(element, definition, parserContext);

        if (StringUtils.hasText(id)) {
            return id;
        }

        // TODO: Check for duplicate using default id here.

        return DEFAULT_PROVIDER_BEAN_ID;
    }
}
