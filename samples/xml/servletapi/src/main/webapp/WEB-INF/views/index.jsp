<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="https://java.sun.com/jsp/jstl/core"%>
<html>
<head>
<title>Welcome</title>
</head>
<body>
  <h1>Home Page</h1>
  <p>
    Anyone can view this page.
  </p>

  <sec:authorize access="authenticated" var="authenticated"/>
  <c:if test="${authenticated}">
    <p>You are currently authenticated</p>
    <dl>
      <dt>HttpServletRequest.getRemoteUser()</dt>
      <dd><c:out value="${remoteUser}"/></dd>
      <dt>HttpServletRequest.getUserPrincipal()</dt>
      <dd><c:out value="${userPrincipal}"/></dd>
      <dt>Authentication</dt>
      <dd><c:out value="${authentication}"/></dd>
    </dl>
  </c:if>
  <ul>
    <li>
      <a href="<c:url value="/authenticate"/>">HttpServletRequest.authenticate(HttpServletResponse)</a>
        - if you are authenticated already will simply return true. Otherwise, will redirect you to the log in page configured in your Spring Security configuration.
    </li>
    <li>
      <a href="<c:url value="/async"/>">AsyncContext.start(Runnable)</a>
        - will automatically transfer the current SecurityContext to the new Thread
    </li>
    <c:choose>
      <c:when test="${authenticated}">
        <li><a href="<c:url value="/logout"/>">HttpServletRequest.logout()</a></li>
      </c:when>
      <c:otherwise>
        <li><a href="<c:url value="/login"/>">Fill out log in form</a> - allows the user to invoke HttpServletRequest.login(String,String)</li>
      </c:otherwise>
    </c:choose>
  </ul>
</body>
</html>
