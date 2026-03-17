rule private_key_pem {
  meta:
    id = "yara-private-key"
    severity = "critical"
    category = "secrets"
    action = "block"
    mode = "audit"
    hook_event = "PreToolUse"
    matcher = "Write|Edit|Read"
  strings:
    $begin = "-----BEGIN" ascii
    $private = "PRIVATE KEY-----" ascii
    $end = "-----END" ascii
  condition:
    $begin and $private and $end
}
