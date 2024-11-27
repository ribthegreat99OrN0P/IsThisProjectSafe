# IsThisProjectSafe

Scans directories for potential malware in project files (`.csproj`, `.vcxproj`, `.vbproj`) and `.suo` files. It detects suspicious configurations and automatically deletes `.suo` files, which may pose security risks.

## Features
- Scans `.csproj`, `.vcxproj`, and `.vbproj` files for:
  - Suspicious build events: `<PreBuildEvent>`, `<PostBuildEvent>`, and `<PreLinkEvent>`.
  - Custom `<Target>` elements with `<Exec>` commands.
  - Suspicious `<COMFileReference>` entries.
  - Imported MSBuild targets (`<Import>`).
- Detects and deletes `.suo` files, as they can potentially contain malware.

## How to Use
1. Clone or download the script.
2. Run the script in a terminal or command prompt:
   ```
   bash
   python main.py <directory_path>
   ```
