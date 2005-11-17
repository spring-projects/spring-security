<%@ page import="org.acegisecurity.acl.basic.SimpleAclEntry" %>
<%@ include file="/WEB-INF/jsp/include.jsp" %>

<html>
<head><title>Administer Permissions</title></head>
<body>
<h1>Administer Permissions</h1>
<P>
<code>
<c:out value="${model.contact}"/>
</code>
<P>
<table cellpadding=3 border=0>
<c:forEach var="acl" items="${model.acls}">
  <c:if test="${acl.class.name eq 'org.acegisecurity.acl.basic.SimpleAclEntry'}">
    <tr>
      <td>
        <code>
          <%
            SimpleAclEntry simpleAcl = ((SimpleAclEntry) pageContext.getAttribute("acl"));
            String permissionBlock = simpleAcl.printPermissionsBlock(); 
          %>
          <%= permissionBlock %>
          [<c:out value="${acl.mask}"/>]
          <c:out value="${acl.recipient}"/>
        </code>
      </td>
      <td>
      <!-- This application doesn't use ACL inheritance, so we can safely use
           the model's contact and know it was directly assigned the ACL -->
        <A HREF="<c:url value="deletePermission.htm"><c:param name="contactId" value="${model.contact.id}"/><c:param name="recipient" value="${acl.recipient}"/></c:url>">Del</A>
      </td>
    </tr>
  </c:if>
</c:forEach>
</table>
<p><a href="<c:url value="addPermission.htm"><c:param name="contactId" value="${model.contact.id}"/></c:url>">Add Permission</a>   <a href="<c:url value="index.htm"/>">Manage</a>
</body>
</html>
