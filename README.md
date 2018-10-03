## AndroidEmbedIT

This script performs the following actions to embed a Metasploit
generated APK file into another legitimate APK.

* decompiles a Metasploit APK file, and any other APK file.
* locates the main Activity entrypoint in the APK being targeted
* copies all Metasploit APK staging code to destination APK
* adjusts the main Activity entrypoint smali file with an *invoke-static* call to kick off the Metasploit stage.
* adjusts the final AndroidManifest.xml with appropriate added permissions
* recompiles, and resigns the final APK file.

All actions are performed within the "~/.ae" directory which is created
during runtime.   The script requires that *keytool*, *jarsigner*, and *apktool*
are installed.  A KALI distribution will work well to run this script on.

