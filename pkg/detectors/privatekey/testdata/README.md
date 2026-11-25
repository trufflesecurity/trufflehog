# Test fixtures

Every key here was generated with ssh-keygen solely for the package tests;
none is or was a real key.

- `encrypted_openssh_ed25519_a16`: OpenSSH ed25519 key encrypted with bcrypt
  at 16 KDF rounds, passphrase `trufflehog-test-fixture` (not in the
  detector's wordlist, so cracking it exercises the uncrackable path).
- `encrypted_openssh_ed25519_a2048`: same at 2048 rounds. Parse-only: no test
  cracks it, because each bcrypt attempt at 2048 rounds costs seconds.
- `encrypted_pem_rsa`: legacy PEM-format RSA key (traditional DEK-Info
  encryption), passphrase `trufflehog-test-fixture`.
- `unencrypted_openssh_ed25519`: unencrypted OpenSSH ed25519 key.
- `crackable_openssh_ed25519_a16`: OpenSSH ed25519 key at 16 rounds whose
  passphrase sits at the head of the detector's built-in wordlist, so a test
  crack succeeds after a few attempts.
- `truncated_openssh_garbage`: the a16 key's binary body cut off inside the
  header, so the metadata parser meets a truncated, hostile-shaped input.
