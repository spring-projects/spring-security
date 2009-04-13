package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.security.core.AuthorityUtils;
import org.springframework.security.userdetails.memory.UserMap;
import org.springframework.security.userdetails.User;
import org.springframework.util.StringUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Iterator;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class UserServiceBeanDefinitionParser extends AbstractUserDetailsServiceBeanDefinitionParser {

    static final String ATT_PASSWORD = "password";
    static final String ATT_NAME = "name";
    static final String ELT_USER = "user";
    static final String ATT_AUTHORITIES = "authorities";
    static final String ATT_PROPERTIES = "properties";
    static final String ATT_DISABLED = "disabled";
    static final String ATT_LOCKED = "locked";

    protected String getBeanClassName(Element element) {
        return "org.springframework.security.userdetails.memory.InMemoryDaoImpl";
    }

    @SuppressWarnings("unchecked")
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        String userProperties = element.getAttribute(ATT_PROPERTIES);
        List<Element> userElts = DomUtils.getChildElementsByTagName(element, ELT_USER);

        if (StringUtils.hasText(userProperties)) {

            if(!CollectionUtils.isEmpty(userElts)) {
                throw new BeanDefinitionStoreException("Use of a properties file and user elements are mutually exclusive");
            }

            BeanDefinition bd = new RootBeanDefinition(PropertiesFactoryBean.class);
            bd.getPropertyValues().addPropertyValue("location", userProperties);
            builder.addPropertyValue("userProperties", bd);

            return;
        }

        if(CollectionUtils.isEmpty(userElts)) {
            throw new BeanDefinitionStoreException("You must supply user definitions, either with <" + ELT_USER + "> child elements or a " +
                "properties file (using the '" + ATT_PROPERTIES + "' attribute)" );
        }

        UserMap users = new UserMap();

        for (Iterator i = userElts.iterator(); i.hasNext();) {
            Element userElt = (Element) i.next();
            String userName = userElt.getAttribute(ATT_NAME);
            String password = userElt.getAttribute(ATT_PASSWORD);
            boolean locked = "true".equals(userElt.getAttribute(ATT_LOCKED));
            boolean disabled = "true".equals(userElt.getAttribute(ATT_DISABLED));

            users.addUser(new User(userName, password, !disabled, true, true, !locked,
                    AuthorityUtils.commaSeparatedStringToAuthorityList(userElt.getAttribute(ATT_AUTHORITIES))));
        }

        builder.addPropertyValue("userMap", users);
    }
}
