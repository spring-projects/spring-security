package org.springframework.security.config.ldap;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.authentication.AbstractUserDetailsServiceBeanDefinitionParser;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @since 2.0
 */
public class LdapUserServiceBeanDefinitionParser extends AbstractUserDetailsServiceBeanDefinitionParser {
    public static final String ATT_SERVER = "server-ref";
    public static final String ATT_USER_SEARCH_FILTER = "user-search-filter";
    public static final String ATT_USER_SEARCH_BASE = "user-search-base";
    public static final String DEF_USER_SEARCH_BASE = "";

    public static final String ATT_GROUP_SEARCH_FILTER = "group-search-filter";
    public static final String ATT_GROUP_SEARCH_BASE = "group-search-base";
    public static final String ATT_GROUP_ROLE_ATTRIBUTE = "group-role-attribute";
    public static final String DEF_GROUP_SEARCH_FILTER = "(uniqueMember={0})";
    public static final String DEF_GROUP_SEARCH_BASE = "";

    static final String ATT_ROLE_PREFIX = "role-prefix";
    static final String ATT_USER_CLASS = "user-details-class";
    static final String ATT_USER_CONTEXT_MAPPER_REF = "user-context-mapper-ref";
    static final String OPT_PERSON = "person";
    static final String OPT_INETORGPERSON = "inetOrgPerson";

    public static final String LDAP_SEARCH_CLASS = "org.springframework.security.ldap.search.FilterBasedLdapUserSearch";
    public static final String PERSON_MAPPER_CLASS = "org.springframework.security.ldap.userdetails.PersonContextMapper";
    public static final String INET_ORG_PERSON_MAPPER_CLASS = "org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper";
    public static final String LDAP_USER_MAPPER_CLASS = "org.springframework.security.ldap.userdetails.LdapUserDetailsMapper";
    public static final String LDAP_AUTHORITIES_POPULATOR_CLASS = "org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator";

    protected String getBeanClassName(Element element) {
        return "org.springframework.security.ldap.userdetails.LdapUserDetailsService";
    }

    protected void doParse(Element elt, ParserContext parserContext, BeanDefinitionBuilder builder) {

        if (!StringUtils.hasText(elt.getAttribute(ATT_USER_SEARCH_FILTER))) {
            parserContext.getReaderContext().error("User search filter must be supplied", elt);
        }

        builder.addConstructorArgValue(parseSearchBean(elt, parserContext));
        builder.getRawBeanDefinition().setSource(parserContext.extractSource(elt));
        builder.addConstructorArgValue(parseAuthoritiesPopulator(elt, parserContext));
        builder.addPropertyValue("userDetailsMapper", parseUserDetailsClassOrUserMapperRef(elt, parserContext));
    }

    static RootBeanDefinition parseSearchBean(Element elt, ParserContext parserContext) {
        String userSearchFilter = elt.getAttribute(ATT_USER_SEARCH_FILTER);
        String userSearchBase = elt.getAttribute(ATT_USER_SEARCH_BASE);
        Object source = parserContext.extractSource(elt);

        if (StringUtils.hasText(userSearchBase)) {
            if(!StringUtils.hasText(userSearchFilter)) {
                parserContext.getReaderContext().error(ATT_USER_SEARCH_BASE + " cannot be used without a " + ATT_USER_SEARCH_FILTER, source);
            }
        } else {
            userSearchBase = DEF_USER_SEARCH_BASE;
        }

        if (!StringUtils.hasText(userSearchFilter)) {
            return null;
        }

        BeanDefinitionBuilder searchBuilder = BeanDefinitionBuilder.rootBeanDefinition(LDAP_SEARCH_CLASS);
        searchBuilder.getRawBeanDefinition().setSource(source);
        searchBuilder.addConstructorArgValue(userSearchBase);
        searchBuilder.addConstructorArgValue(userSearchFilter);
        searchBuilder.addConstructorArgValue(parseServerReference(elt, parserContext));

        return (RootBeanDefinition) searchBuilder.getBeanDefinition();
    }

    static RuntimeBeanReference parseServerReference(Element elt, ParserContext parserContext) {
        String server = elt.getAttribute(ATT_SERVER);
        boolean requiresDefaultName = false;

        if (!StringUtils.hasText(server)) {
            server = BeanIds.CONTEXT_SOURCE;
            requiresDefaultName = true;
        }

        RuntimeBeanReference contextSource = new RuntimeBeanReference(server);
        contextSource.setSource(parserContext.extractSource(elt));
        registerPostProcessorIfNecessary(parserContext.getRegistry(), requiresDefaultName);

        return contextSource;
    }

    private static void registerPostProcessorIfNecessary(BeanDefinitionRegistry registry, boolean defaultNameRequired) {
        if (registry.containsBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR)) {
            if (defaultNameRequired) {
                BeanDefinition bd = registry.getBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR);
                bd.getPropertyValues().addPropertyValue("defaultNameRequired", Boolean.valueOf(defaultNameRequired));
            }
            return;
        }

        BeanDefinitionBuilder bdb = BeanDefinitionBuilder.rootBeanDefinition(ContextSourceSettingPostProcessor.class);
        bdb.addPropertyValue("defaultNameRequired", Boolean.valueOf(defaultNameRequired));
        registry.registerBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR, bdb.getBeanDefinition());
    }

    static BeanMetadataElement parseUserDetailsClassOrUserMapperRef(Element elt, ParserContext parserContext) {
        String userDetailsClass = elt.getAttribute(ATT_USER_CLASS);
        String userMapperRef = elt.getAttribute(ATT_USER_CONTEXT_MAPPER_REF);

        if (StringUtils.hasText(userDetailsClass) && StringUtils.hasText(userMapperRef)) {
            parserContext.getReaderContext().error("Attributes " + ATT_USER_CLASS + " and " + ATT_USER_CONTEXT_MAPPER_REF
                    + " cannot be used together.", parserContext.extractSource(elt));
        }

        if (StringUtils.hasText(userMapperRef)) {
            return new RuntimeBeanReference(userMapperRef);
        }

        RootBeanDefinition mapper;

        if (OPT_PERSON.equals(userDetailsClass)) {
            mapper = new RootBeanDefinition(PERSON_MAPPER_CLASS, null, null);
        } else if (OPT_INETORGPERSON.equals(userDetailsClass)) {
            mapper = new RootBeanDefinition(INET_ORG_PERSON_MAPPER_CLASS, null, null);
        } else {
            mapper = new RootBeanDefinition(LDAP_USER_MAPPER_CLASS, null, null);
        }

        mapper.setSource(parserContext.extractSource(elt));

        return mapper;
    }

    static RootBeanDefinition parseAuthoritiesPopulator(Element elt, ParserContext parserContext) {
        String groupSearchFilter = elt.getAttribute(ATT_GROUP_SEARCH_FILTER);
        String groupSearchBase = elt.getAttribute(ATT_GROUP_SEARCH_BASE);
        String groupRoleAttribute = elt.getAttribute(ATT_GROUP_ROLE_ATTRIBUTE);
        String rolePrefix = elt.getAttribute(ATT_ROLE_PREFIX);

        if (!StringUtils.hasText(groupSearchFilter)) {
            groupSearchFilter = DEF_GROUP_SEARCH_FILTER;
        }

        if (!StringUtils.hasText(groupSearchBase)) {
            groupSearchBase = DEF_GROUP_SEARCH_BASE;
        }

        BeanDefinitionBuilder populator = BeanDefinitionBuilder.rootBeanDefinition(LDAP_AUTHORITIES_POPULATOR_CLASS);
        populator.getRawBeanDefinition().setSource(parserContext.extractSource(elt));
        populator.addConstructorArgValue(parseServerReference(elt, parserContext));
        populator.addConstructorArgValue(groupSearchBase);
        populator.addPropertyValue("groupSearchFilter", groupSearchFilter);
        populator.addPropertyValue("searchSubtree", Boolean.TRUE);

        if (StringUtils.hasText(rolePrefix)) {
            if ("none".equals(rolePrefix)) {
                rolePrefix = "";
            }
            populator.addPropertyValue("rolePrefix", rolePrefix);
        }

        if (StringUtils.hasLength(groupRoleAttribute)) {
            populator.addPropertyValue("groupRoleAttribute", groupRoleAttribute);
        }

        return (RootBeanDefinition) populator.getBeanDefinition();
    }
}
