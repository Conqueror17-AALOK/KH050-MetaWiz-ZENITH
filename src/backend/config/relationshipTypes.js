// Taxonomy of privilege/control relationships in the identity graph.
// `weight` = relative exploit difficulty (1 = trivial for an attacker to abuse,
// 10 = hard/noisy). Lower total path weight = easier real-world attack path,
// so path-finding treats this as edge cost for a "cheapest path" query.

const RELATIONSHIP_TYPES = {
  MEMBER_OF: { label: 'MemberOf', weight: 1, desc: 'Is a member of a group' },
  ADMIN_TO: { label: 'AdminTo', weight: 2, desc: 'Has local admin rights on' },
  CAN_RDP: { label: 'CanRDP', weight: 3, desc: 'Can remote desktop into' },
  HAS_SESSION: { label: 'HasSession', weight: 2, desc: 'Has an active/cached session on' },
  CAN_RESET_PASSWORD_OF: { label: 'CanResetPasswordOf', weight: 4, desc: 'Can reset the password of' },
  OWNS: { label: 'Owns', weight: 3, desc: 'Owns the object (full control)' },
  TRUSTED_BY: { label: 'TrustedBy', weight: 5, desc: 'Is a trusted delegate for' },
  EXECUTE_DCOM: { label: 'ExecuteDCOM', weight: 4, desc: 'Can execute code via DCOM on' },
  // Phase 2: Real-world Active Directory & IAM attack techniques
  // 1. Kerberoasting (MITRE T1558.003): Any domain user can request TGS tickets for SPN-bearing accounts and crack hashes offline. Very low friction.
  KERBEROASTABLE: { label: 'Kerberoastable', weight: 2, desc: 'Service account with SPN vulnerable to offline Kerberoasting ticket cracking' },
  // 2. GenericAll / ACL abuse (MITRE T1222.001): Full DACL control over object (reset passwords, write arbitrary attributes). Trivial to execute.
  GENERIC_ALL: { label: 'GenericAll', weight: 1, desc: 'Direct full control / ACL abuse over target object' },
  // 3. GPO Abuse (MITRE T1484.001): Modifying a Group Policy Object compromises all endpoints in the linked container on policy refresh.
  GPO_APPLIED_TO: { label: 'GPOAppliedTo', weight: 3, desc: 'Group Policy Object enforced on container/machines enabling administrative control' },
};

module.exports = { RELATIONSHIP_TYPES };
