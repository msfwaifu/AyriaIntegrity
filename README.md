AyriaIntegrity plugin
---

This plugin aims to open games up for modding. 
As anti-cheat and anti-piracy tools get more advanced they start to add anti-tampering.
This is ofcourse useful against inexperienced developers but it's also a pain for modders.
Especially as most systems remove the ability to debug the application.

As such we try to remove some common protections.
These will not enable piracy or in any way disable the 'DRM' part of DRMs;
unless those parts are so intertwined with the anti-tampering that one can't remove one without the other.

Any DRM related system (e.g. Steams CEG) will be backed by anti-piracy checks in the relevant part of AyriaPlatform.


Extensionloading
--

This module is intended to be loaded via Ayrias bootstrap module (https://github.com/AyriaPublic/NativeBootstrap), as such the user may drag and drop it into their ./Plugins/ directory. 
The plugin loads protection specific configurations from the ./Plugins/Integrity/ directory.
