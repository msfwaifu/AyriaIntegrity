# Ayria Integrity plugin

This plugin aims to open games up for modding. 
As anti-cheat and anti-piracy tools get more advanced they start to add anti-tampering.
This is ofcourse useful against inexperienced developers but it's also a pain for modders.
Especially as most systems remove the ability to debug the application.

As such we try to remove some common protections.
These will not enable piracy or in any way disable the 'DRM' part of DRMs;
unless those parts are so intertwined with the anti-tampering that one can't remove one without the other.

Any DRM related system (e.g. Steams CEG) will be backed by anti-piracy checks in the relevant part of AyriaPlatform.

## Plugin loading

The plugin should, like all other plugins, be placed in the games `./Plugins/` directory where it gets loaded by the [Bootstrap](https://github.com/AyriaPublic/NativeBootstrap) module which is injected into the game by the desktop client. The protection configuration is loaded from the `./Plugins/AyriaIntegrity/` directory.
