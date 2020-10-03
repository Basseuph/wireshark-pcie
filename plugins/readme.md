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

1. various header fields are not fully processed and displayed as per dependency or marked as unused properly
2. various checks and calculations are missing

