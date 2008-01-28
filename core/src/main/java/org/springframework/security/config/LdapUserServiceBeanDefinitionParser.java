package org.springframework.security.config;

import org.springframework.security.userdetails.ldap.LdapUserDetailsService;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.util.StringUtils;
import org.springframework.util.Assert;

import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class LdapUserServiceBeanDefinitionParser extends AbstractUserDetailsServiceBeanDefinitionParser {
    private static final String ATT_SERVER = "server-ref";
    public static final String ATT_USER_SEARCH_FILTER = "user-search-filter";
    public static final String ATT_USER_SEARCH_BASE = "user-search-base";
    public static final String DEF_USER_SEARCH_BASE = "";

    public static final String ATT_GROUP_SEARCH_FILTER = "group-search-filter";
    public static final String ATT_GROUP_SEARCH_BASE = "group-search-base";
    public static final String DEF_GROUP_SEARCH_FILTER = "(uniqueMember={0})";
    public static final String DEF_GROUP_SEARCH_BASE = "ou=groups";

    protected Class getBeanClass(Element element) {
        return LdapUserDetailsService.class;
    }

    protected void doParse(Element elt, ParserContext parserContext, BeanDefinitionBuilder builder) {
        String server = elt.getAttribute(ATT_SERVER);

        if (!StringUtils.hasText(server)) {
            server = BeanIds.CONTEXT_SOURCE;
        }

        String userSearchFilter = elt.getAttribute(ATT_USER_SEARCH_FILTER);
        Assert.hasText(userSearchFilter, "User search filter must be supplied");
        String userSearchBase = elt.getAttribute(ATT_USER_SEARCH_BASE);

        if (!StringUtils.hasText(userSearchBase)) {
            userSearchBase = DEF_USER_SEARCH_BASE;
        }

        String groupSearchFilter = elt.getAttribute(ATT_GROUP_SEARCH_FILTER);
        String groupSearchBase = elt.getAttribute(ATT_GROUP_SEARCH_BASE);

        if (!StringUtils.hasText(groupSearchFilter)) {
            groupSearchFilter = DEF_GROUP_SEARCH_FILTER;
        }

        if (!StringUtils.hasText(groupSearchBase)) {
            groupSearchBase = DEF_GROUP_SEARCH_BASE;
        }

        RuntimeBeanReference contextSource = new RuntimeBeanReference(server);
        BeanDefinition search = new RootBeanDefinition(FilterBasedLdapUserSearch.class);
        search.getConstructorArgumentValues().addIndexedArgumentValue(0, userSearchBase);
        search.getConstructorArgumentValues().addIndexedArgumentValue(1, userSearchFilter);
        search.getConstructorArgumentValues().addIndexedArgumentValue(2, contextSource);

        BeanDefinition populator = new RootBeanDefinition(DefaultLdapAuthoritiesPopulator.class);
        populator.getConstructorArgumentValues().addIndexedArgumentValue(0, contextSource);
        populator.getConstructorArgumentValues().addIndexedArgumentValue(1, groupSearchBase);
        populator.getPropertyValues().addPropertyValue("groupSearchFilter", groupSearchFilter);

        builder.addConstructorArg(search);
        builder.addConstructorArg(populator);

        LdapConfigUtils.registerPostProcessorIfNecessary(parserContext.getRegistry());
    }
}
