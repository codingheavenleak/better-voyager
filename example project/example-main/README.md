# ScyVisor Hypervisor Anti-cheat Bypass Framework

## Overview

ScyVisor is a powerful hypervisor-level anti-cheat bypass framework designed for advanced game modification and cheat development. This example project demonstrates the basic implementation of ScyVisor in a client application, showcasing its core functionalities.


## Project Structure

- `Usage.cpp`: Main application demonstrating basic ScyVisor usage
- `ScyVisor.h`: Header file containing ScyVisor API declarations
- `ScyVisorLib.lib`: Pre-compiled library containing ScyVisor API implementation
- `comm.asm`: Assembly file for  communication

## Getting Started

1. Ensure you have Visual Studio 2022 or later installed with C++20 support.
2. Include `ScyVisor.h`, `ScyVisorLib.lib` and `comm.asm` in your project.
3. Make sure you linked the ScyVisorLib.lib in your Projectproperties.

## Basic Usage

The `Usage.cpp` file demonstrates the following basic operations:

1. Initializing ScyVisor
2. Retrieving the current process's Directory Table Base
3. Loading necessary kernel module addresses
4. Getting the Process ID (PID) of a target process
5. Retrieving the base address and DTB of the target process

## Important Note

This example project does not showcase all capabilities of the ScyVisor API. For a complete understanding of ScyVisor's full potential, please refer to our comprehensive API documentation.

## API Documentation

For detailed information about all available functions, data structures, and advanced usage, please visit our official API documentation:

[ScyVisor API Documentation](https://scyvisor.gitbook.io/scyvisor)

## Support

For questions, issues, or feature requests, please open an ticket on our Discord: https://discord.gg/scyvisor
