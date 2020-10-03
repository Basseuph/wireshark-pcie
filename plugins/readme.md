# Wireshark PCIe TLP dissector written in LUA script

## Description

The wireshark plugin is capable of dissecting fully captured TLPs, also embedded into network packets.
It is also capable of recognizing padding data (0x00 bytes) between TLPs, which are marked as such and added to the tree.

The script has been adapted from this one https://github.com/sora/wireshark-pcie

## Install

copy the lua script file to .config/wireshark/plugins/ for user local installation

## Editing & Debugging

During debugging Wireshark support reloading the LUA dissectors during runtime with the shortcut Ctrl + Shift + L

## NOTEs

## TODOs

1. add FMT / TYPE based decoding of TLPs
 -> add 4th DW header decoding
2. add field for number of TLPs field to root of PCIe tree
3. add field for number of padding bytes to root of PCIe tree
4. add field for number of TLP bytes to root of PCIe tree
