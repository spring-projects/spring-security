<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>

<html>
<body>

<h1>OpenID Sample Home Page</h1>

<sec:authentication property='principal.newUser' var='isNew' />
<p>
Welcome<c:if test="${!isNew}"> back,</c:if> <sec:authentication property='principal.name' />!
</p>
<c:if test="${isNew}">
<p>
As a first time user of this site, your OpenID identity has been registered
by the application and will be recognized if you return.
</p>
</c:if>

<h3>Technical Information</h3>
<p>
Your principal object is....: <%= request.getUserPrincipal() %>
</p>
<p><a href="j_spring_security_logout">Logout</a>
</body>
</html>
