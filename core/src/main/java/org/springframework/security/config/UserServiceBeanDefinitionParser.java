package org.springframework.security.config;

import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.security.userdetails.memory.InMemoryDaoImpl;
import org.springframework.security.userdetails.memory.UserMap;
import org.springframework.security.userdetails.User;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.util.xml.DomUtils;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Iterator;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class UserServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    static final String ATT_PASSWORD = "password";
	static final String ATT_NAME = "name";
	static final String ELT_USER = "user";
	static final String ATT_AUTHORITIES = "authorities";

	protected Class getBeanClass(Element element) {
        return InMemoryDaoImpl.class;
    }

    protected void doParse(Element element, BeanDefinitionBuilder builder) {
        List userElts = DomUtils.getChildElementsByTagName(element, ELT_USER);
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

    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) throws BeanDefinitionStoreException {
        String id = super.resolveId(element, definition, parserContext);

        if (StringUtils.hasText(id)) {
            return id;
        }

        // TODO: Check for duplicate using default id here.

        return BeanIds.USER_DETAILS_SERVICE;
    }
}
