# .dmp Security

A proof-of-concept tool that leverages Windows kernel dump files for enhanced security analysis.

## Overview

**.dmp Security** was created to take advantage of the introduction of full live kernel dumps in Windows 11. It allows you to capture a live snapshot of the kernel memory and perform various security checks entirely from user mode—no kernel driver required.

## Features

- **Live Kernel Dump** (`-ld`):  
  Create a live kernel dump (*requires administrative privileges and Win11*).

- **Pagewalk Analysis** (`-p`):  
  Walk through all kernel pages and trigger two specific callbacks:
  - **Executable Page Callback**: Logs whenever an executable page is found outside the loaded modules.
  - **Page Start Callback**: Logs when a page begins with a DOS header and is outside the loaded modules.  
    *Note: This logs a considerable amount of pages in a normal system as well. Whether it be signature scanning or something else, it's up to your imagination to mitigate.*

- **Driver Extraction** (`-d`):  
  Extract a driver from the dump and save it to a file.

- **Integrity Check** (`-i`):  
  Perform a disk-versus-memory integrity check on a specified driver by:
  - Comparing section headers.
  - Conducting byte/instruction-level comparisons on executable pages.
  - Mitigating false positives (due to factors like Retpoline, import optimization, and KASLR) by skipping mismatched RVAs if a Dynamic Value Relocation Table (DVRT) entry is present.  
    *Note: This is a very simple approach and as you might imagine, it will lead to false negatives if the mismatch happens at one of these locations. Check out the integrity code and [DVRT parser](https://github.com/Life45/dmputils/blob/main/external/dvrtparser/dvrtparser.h) for nuances and workarounds.*

This project was developed over a weekend as a quick proof-of-concept. There is plenty of room for expansion, so feel free to explore additional security checks and improvements.
