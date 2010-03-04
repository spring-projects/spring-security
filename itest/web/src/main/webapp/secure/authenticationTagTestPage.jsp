<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<html>
<body>
<h1>Authentication Tag Test Page</h1>

<p>
<ul>
<li>This is the authentication name: <sec:authentication property="name"/></li>
<li>This is the principal.username: <sec:authentication property="principal.username"/></li>
<li>This is the unescaped authentication name: <sec:authentication property="name" htmlEscape="false"/></li>
<li>This is the unescaped principal.username: <sec:authentication property="principal.username" htmlEscape="false"/></li>

</ul
</p>
</body>

</html>


