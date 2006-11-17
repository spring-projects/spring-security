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
<c:forEach var="acl" items="${model.acl.entries}">
    <tr>
      <td>
        <code>
          <c:out value="${acl}"/>
        </code>
      </td>
      <td>
      <A HREF="<c:url value="deletePermission.htm"><c:param name="contactId" value="${model.contact.id}"/><c:param name="sid" value="${acl.sid.principal}"/><c:param name="permission" value="${acl.permission.mask}"/></c:url>">Del</A>
      </td>
    </tr>
</c:forEach>
</table>
<p><a href="<c:url value="addPermission.htm"><c:param name="contactId" value="${model.contact.id}"/></c:url>">Add Permission</a>   <a href="<c:url value="index.htm"/>">Manage</a>
</body>
</html>
