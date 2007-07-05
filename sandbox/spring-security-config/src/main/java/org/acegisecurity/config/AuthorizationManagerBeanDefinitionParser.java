package org.acegisecurity.config;

import org.acegisecurity.AccessDecisionManager;
import org.acegisecurity.vote.AffirmativeBased;
import org.acegisecurity.vote.AuthenticatedVoter;
import org.acegisecurity.vote.ConsensusBased;
import org.acegisecurity.vote.RoleVoter;
import org.acegisecurity.vote.UnanimousBased;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class AuthorizationManagerBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {
	// ~ static initializers
	// ================================================================================================

	public static final String ROLE_VOTER_ELE = "role-voter";

	public static final String AUTHENTICATED_VOTER_ELE = "authenticated-voter";

	public static final String STRATEGY_ATTRIBUTE = "strategy";

	// ~ Method
	// ================================================================================================

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		return createBeanDefinition(element, parserContext);
	}

	private RootBeanDefinition createBeanDefinition(Element element, ParserContext parserContext) {
		ManagedList decisionVoters = new ManagedList();

		Element roleVoterEle = DomUtils.getChildElementByTagName(element, ROLE_VOTER_ELE);
		Element authVoterEle = DomUtils.getChildElementByTagName(element, AUTHENTICATED_VOTER_ELE);
		
		if(roleVoterEle!=null && roleVoterEle.getLocalName().equals(ROLE_VOTER_ELE)) {
			decisionVoters.add(new RootBeanDefinition(RoleVoter.class));
		} 
		if (authVoterEle!=null && authVoterEle.getLocalName().equals(AUTHENTICATED_VOTER_ELE)) {
			decisionVoters.add(new RootBeanDefinition(AuthenticatedVoter.class));
		}
		
		String strategy = element.getAttribute(STRATEGY_ATTRIBUTE);
		if (StringUtils.hasLength(strategy)) {
			if (strategy.equals("affirmative")) {
				return createAccessDecisionManager(AffirmativeBased.class, decisionVoters);
			}
			else if (strategy.equals("consensus")) {
				return createAccessDecisionManager(ConsensusBased.class, decisionVoters);
			}
			else if (strategy.equals("unanimous")) {
				return createAccessDecisionManager(UnanimousBased.class, decisionVoters);
			}
		}
		else {
			return createAccessDecisionManagerAffirmativeBased();
		}
		return null;
	}

	protected static RootBeanDefinition createAccessDecisionManagerAffirmativeBased() {
		ManagedList decisionVoters = new ManagedList();
		decisionVoters.add(new RootBeanDefinition(AuthenticatedVoter.class));
		decisionVoters.add(new RootBeanDefinition(RoleVoter.class));
		return createAccessDecisionManager(AffirmativeBased.class, decisionVoters);
	}

	protected static RootBeanDefinition createAccessDecisionManager(Class clazz, ManagedList decisionVoters) {
		RootBeanDefinition accessDecisionManager = new RootBeanDefinition(clazz);
		accessDecisionManager.getPropertyValues().addPropertyValue("allowIfAllAbstainDecisions", Boolean.FALSE);
		accessDecisionManager.getPropertyValues().addPropertyValue("decisionVoters", decisionVoters);
		return accessDecisionManager;
	}

}
