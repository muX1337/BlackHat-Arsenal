# Introducing Serberus, a multi headed embedded hardware interface tool.

## Description
The Serberus is a multi-headed hardware hacking tool designed to easily connect to your target. It has 4 channels and has headers to interface with UART, JTAG, SPI, I2C and SWD. Serberus is an evolution of the TIMEP, created by a fellow Google employee a few years ago. It has a similar level shifter design to allow you to connect to any logic voltage between 1.65V and 5.5V, there is even a setting to allow you to match the voltage of your target if it is using a non-standard voltage. The project is free and open source with all board layouts, design files and schematics published.

During this arsenal talk I will introduce and demonstrate the Serberus on devices from a simple wifi router as well as multi-serial avionics and electric vehicle systems. I will demonstrate my methodology for rapidly locating, timing and connecting to UARTs beyond just probing likely connection points on a target board.

## Code
https://github.com/google/serberus
