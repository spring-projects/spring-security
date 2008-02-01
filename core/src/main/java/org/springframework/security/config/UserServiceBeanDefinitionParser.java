package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.userdetails.memory.InMemoryDaoImpl;
import org.springframework.security.userdetails.memory.UserMap;
import org.springframework.security.userdetails.User;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.Assert;
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

	protected Class getBeanClass(Element element) {
        return InMemoryDaoImpl.class;
    }

    protected void doParse(Element element, BeanDefinitionBuilder builder) {
        String userProperties = element.getAttribute(ATT_PROPERTIES);
        List userElts = DomUtils.getChildElementsByTagName(element, ELT_USER);

        if (StringUtils.hasText(userProperties)) {
            Assert.isTrue(userElts.isEmpty(), "Use of a properties file ('" + ATT_PROPERTIES + "' attribute) and <" +
                    ELT_USER + "> elements are mutually exclusive.");

            BeanDefinition bd = new RootBeanDefinition(PropertiesFactoryBean.class);
            bd.getPropertyValues().addPropertyValue("location", userProperties);
            builder.addPropertyValue("userProperties", bd);

            return;
        }

        Assert.notEmpty(userElts, "You must supply user definitions, either with <" + ELT_USER + "> child elements or a " +
                "properties file (specified with the '" + ATT_PROPERTIES + "' attribute)" );

        UserMap users = new UserMap();

        for (Iterator i = userElts.iterator(); i.hasNext();) {
            Element userElt = (Element) i.next();
            String userName = userElt.getAttribute(ATT_NAME);
            String password = userElt.getAttribute(ATT_PASSWORD);

            users.addUser(new User(userName, password, true, true, true, true,
                    AuthorityUtils.commaSeparatedStringToAuthorityArray(userElt.getAttribute(ATT_AUTHORITIES))));
        }

        builder.addPropertyValue("userMap", users);
    }
}
