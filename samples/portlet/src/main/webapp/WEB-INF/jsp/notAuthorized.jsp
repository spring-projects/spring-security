<%@ include file="/WEB-INF/jsp/include.jsp" %>

<h1><spring:message code="exception.notAuthorized.title"/></h1>

<p><spring:message code="exception.notAuthorized.message"/><br>

<spring:message code="exception.contactAdmin"/></p>

<p style="text-align:center;"><a href="<portlet:renderURL portletMode="view"/>">- <spring:message code="button.home"/> -</a></p>
