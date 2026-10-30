// OpenTPRM default-deny Cedar policies (M0)
// Agents never approve, finalize, or administer (SOD-4 / IAM).
forbid (
  principal is Agent,
  action in [Action::"risk:approve", Action::"exception:approve",
             Action::"assessment:finalize", Action::"admin:any",
             Action::"identity:manage", Action::"policy:manage", Action::"export:bulk"],
  resource
);

// Restricted records override every role unless allow-listed or break-glass.
forbid (principal, action, resource)
when {
  resource has restricted && resource.restricted &&
  !(resource has allowlist && resource.allowlist.contains(principal.subject)) &&
  !(context has breakGlass && context.breakGlass)
};

// Authenticated workforce may read health metadata.
permit (
  principal is User,
  action == Action::"system:health",
  resource
);

// Risk analysts may read vendors (coarse; object checks still apply).
permit (
  principal is User,
  action in [Action::"vendor:read", Action::"engagement:read", Action::"assessment:read", Action::"finding:read"],
  resource
)
when { principal.roles.contains("risk_analyst") || principal.roles.contains("tprm_program_manager") || principal.roles.contains("approver") || principal.roles.contains("auditor") || principal.roles.contains("viewer") };

permit (
  principal is User,
  action in [Action::"vendor:write", Action::"engagement:write", Action::"intake:submit", Action::"assessment:transition",
             Action::"finding:write", Action::"suggestion:create", Action::"change_request:create"],
  resource
)
when { principal.roles.contains("risk_analyst") || principal.roles.contains("tprm_program_manager") || principal.roles.contains("relationship_owner") };

permit (
  principal is User,
  action in [Action::"risk:approve", Action::"exception:approve", Action::"assessment:finalize"],
  resource
)
when { principal.roles.contains("approver") && context has aal && context.aal >= 2 };

permit (
  principal is User,
  action == Action::"export:bulk",
  resource
)
when {
  (principal.roles.contains("approver") || principal.roles.contains("tprm_program_manager") || principal.roles.contains("auditor")) &&
  context has aal && context.aal >= 2
};

permit (
  principal is User,
  action == Action::"admin:any",
  resource
)
when { principal.roles.contains("system_administrator") || principal.roles.contains("security_administrator") };

permit (
  principal is User,
  action == Action::"evidence:read_content",
  resource
)
when {
  (principal.roles.contains("risk_analyst") || principal.roles.contains("auditor")) &&
  context has aal && context.aal >= 2
};

permit (
  principal is Agent,
  action in [Action::"vendor:read", Action::"engagement:read", Action::"assessment:read", Action::"finding:read"],
  resource
)
when { principal has scopes && principal.scopes.contains("tprm.read") };

permit (
  principal is Agent,
  action == Action::"evidence:read_content",
  resource
)
when { principal has scopes && principal.scopes.contains("tprm.content.read") };
