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
 * @author luke
 * @version $Id$
 */
public class UserServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    public static final String DEFAULT_ID = "_userDetailsService";

    protected Class getBeanClass(Element element) {
        return InMemoryDaoImpl.class;
    }


    protected void doParse(Element element, BeanDefinitionBuilder builder) {
        List userElts = DomUtils.getChildElementsByTagName(element, "user");
        UserMap users = new UserMap();

        for (Iterator i = userElts.iterator(); i.hasNext();) {
            Element userElt = (Element) i.next();
            String userName = userElt.getAttribute("name");
            String password = userElt.getAttribute("password");

            users.addUser(new User(userName, password, true, true, true, true,
                    AuthorityUtils.commaSeparatedStringToAuthorityArray(userElt.getAttribute("authorities"))));
        }

        builder.addPropertyValue("userMap", users);


    }

    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) throws BeanDefinitionStoreException {
        String id = super.resolveId(element, definition, parserContext);

        if (StringUtils.hasText(id)) {
            return id;
        }

        // TODO: Check for duplicate using default id here.

        return DEFAULT_ID;
    }
}
