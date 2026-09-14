# Troubleshooting and safety

Troubleshooting the FC1B patch: if the Intel flash descriptor signature is not found in the first 4096 bytes, the dump is incomplete (re-read the full chip, check clip contact and the 3.3 V supply) or only the BIOS region was dumped without the descriptor; patch only full dumps. If no 00FCAA or 00FDAA password patterns are found, the entries sit outside the scanned window or use a newer firmware layout; scan the whole file for the patterns before giving up, and keep the original dump safe. If the machine will not boot after flashing, reflash the untouched original dump first and retry.

Safety and legality: it is legal to unlock a machine you own or are explicitly authorized to service, so only unlock those. The official route is Dell support with proof of ownership (original invoice or ownership transfer); Dell can issue a master unlock code for a locked commercial machine. BIOS password recovery is intended for regaining access to your own hardware, not for circumventing security on machines that belong to someone else.

Scope limits: this procedure clears the BIOS or UEFI firmware password, the lock that blocks F2 setup and system boot. It does not decrypt a hard drive or SSD password, does not remove a Windows login password, and does not disable Computrace or Absolute persistence. HDD passwords need the drive's own master password route, and Windows passwords need operating system level recovery.

Data safety while programming: never mix regions from different dumps, always keep a verified original backup, check that the patched file size equals the original size, and never interrupt a flash write. If the clip loses contact during a read, dump again until two consecutive reads match byte for byte.
