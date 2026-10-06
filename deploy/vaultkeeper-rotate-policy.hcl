# Vault ACL policy "vaultkeeper-rotate": everything `vaultkeeper rotate-keyring`
# and the keyring line of `vaultkeeper status` need, and nothing else.
#   vault policy write vaultkeeper-rotate deploy/vaultkeeper-rotate-policy.hcl
path "sys/rotate" {
  capabilities = ["update", "sudo"]
}

path "sys/key-status" {
  capabilities = ["read"]
}
