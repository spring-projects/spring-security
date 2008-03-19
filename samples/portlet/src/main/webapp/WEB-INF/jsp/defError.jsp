<%@ include file="/WEB-INF/jsp/include.jsp" %>

<h1><spring:message code="exception.generalError.title"/></h1>

<p>${exception.localizedMessage == null ? exception : exception.localizedMessage }<br/>
<spring:message code="exception.contactAdmin"/></p>

<p>${exception.class}</p>

<p style="text-align:center;"><a href="<portlet:renderURL portletMode="view"/>">- <spring:message code="button.home"/> -</a></p>
