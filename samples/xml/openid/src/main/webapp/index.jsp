<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>

<html>
<body>

<h1>OpenID Sample Home Page</h1>

<p><strong>
NOTE: The OpenID 1.0 and 2.0 protocols have been deprecated and users are
<a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
to <a href="https://openid.net/connect/">OpenID Connect</a>, which is supported by <code>spring-security-oauth2</code>.
</strong></p>

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
<p><a href="logout">Logout</a>
</body>
</html>
