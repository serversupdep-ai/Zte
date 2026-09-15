# Legacy Dell suffix master password generator

The legacy Dell BIOS password suffixes have known keygen algorithms that decrypt or generate the master password directly from the service tag: 595B, 2A7B, A95B, D35B, 1D3B, 1F5A, 1F66, 6FF1, BF97, and E7A8. The input is the seven character service tag plus the suffix shown on the lock screen, for example ABC1234-1F66, and the generator computes the master password or a short list of candidate passwords for that machine.

Known quirks: for the 6FF1 suffix the generator has a known bug, so generate the password using the BF97 suffix instead with the same service tag, for example use ABC1234-BF97 when the screen shows ABC1234-6FF1. The E7A8 suffix produces two candidate passwords; try both. After typing the generated password at the BIOS lock screen, confirm with Ctrl+Enter+Enter on models that need it; a plain Enter may not clear the lock on some machines.

Tools for the legacy suffixes: bios-pw.org is the classic online generator; DellBIOSTools on GitHub has a Password Generator tab; and this workspace ships the same algorithms as a command line tool: run `python3 tools/dell_keygen.py ABC1234-1F66`. Public test vector for validation: service tag DELLSUX with suffix 1F66 computes master password qHXaL0ntli6Gu4c0.

The FC1B, CF1B, and 8FC8 suffixes are NOT supported by any public keygen: no algorithm exists that decrypts an FC1B master password from the service tag, because these machines verify the password inside the firmware. For FC1B, CF1B, and 8FC8 use the BIOS dump patch procedure or the official Dell support unlock with proof of ownership.
