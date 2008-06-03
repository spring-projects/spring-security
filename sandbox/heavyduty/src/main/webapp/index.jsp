<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<html>
<body>
<h1>HeavyDuty App Home Page</h1>
<p>
Anyone can view this page.
</p>
<p>
Test multi-action controller <a href="testMulti.htm?action=step1">SEC-830</a>.
</p>
<p>
Your principal object is....: <%= request.getUserPrincipal() %>
</p>
<h3>Restricted Pages ...</h3>
<p><a href="secure/index.jsp">Secure page</a></p>
<p><a href="secure/extreme/index.jsp">Extremely secure page</a></p>
</body>
</html>