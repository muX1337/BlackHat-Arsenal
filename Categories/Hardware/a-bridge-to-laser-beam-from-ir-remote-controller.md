# a bridge to laser beam from IR remote controller

## Description
This summer, Michihiro Imaoka presented IR-BadUSB at the Black Hat USA 2022 Arsenal.

This IR-BadUSB allows an attacker to control a BadUSB plugged into a target's PC with an infrared remote control. Since this IR-BadUSB uses a household infrared remote control, the attacker and the IR-BadUSB must be within the infrared range of this remote control. Basically, the target and the attacker must be in the same room. Therefore, various improvements have been made to extend the reach of this IR-BadUSB.

This is one such attempt. This is an attempt to extend the limited range of infrared remote control units for home appliances by converting them into laser beams and irradiating them. Let us explain the method. The module that emits the laser beam has a wavelength of 940 nm, the same wavelength as the infrared ray for home appliances.

The transmitted beam from the infrared remote control for home appliances is received by an infrared receiver such as VS1838B. After adding a 38 KHz subcarrier to the received signal, the laser module is driven by a transistor or similar device.

Perhaps if IR-BadUSB is located near a window, it would be possible to control IR-BadUSB from outdoors. Even if the IR-BadUSB is not near a window, it may be possible to control other IR-BadUSBs if the IR laser beam is reflected and diffused by something inside the room. Infrared light is invisible to the human eye, so the target will not notice it. The only way to prevent this might be to close the curtains or lower the blinds.

Operating the IR-BadUSB with an infrared laser beam does not require a PC or other large device, since it is a remote control for home appliances. If you have a remote control for home appliances that you have used to operate IR-BadUSB, you can use that remote control. No separate programming is required.

## Code
https://github.com/imaoca/irBadUSBbyButton
