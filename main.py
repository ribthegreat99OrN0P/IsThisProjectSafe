import os
import xml.etree.ElementTree as ET

def main():
    print("Enter the directory to scan:")
    directory_path = input()

    if not directory_path or not os.path.exists(directory_path):
        print("Invalid directory path.")
        return

    # File extensions to scan
    project_extensions = ["*.csproj", "*.vcxproj", "*.vbproj"]
    project_files = []

    for root, _, files in os.walk(directory_path):
        for ext in project_extensions:
            for file in files:
                if file.endswith(tuple(ext.strip("*"))):
                    project_files.append(os.path.join(root, file))

    print("Scanning project files...")
    for file in project_files:
        print(f"Scanning {file}...")
        scan_project_file(file)
        
    print("Scanning for .suo files...")
    scan_and_delete_suo_files(directory_path)

    print("Scanning complete.")

def scan_project_file(file_path):
    try:
        # Parse the project file as an XML document
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Check for PreBuildEvent, PostBuildEvent, and PreLinkEvent
        check_event(file_path, root, "PreBuildEvent")
        check_event(file_path, root, "PostBuildEvent")
        check_event(file_path, root, "PreLinkEvent")  # Specific to .vcxproj

        # Check for custom <Target> elements with Exec Command
        targets = root.findall(".//Target")
        for target in targets:
            exec_command = target.find(".//Exec")
            if exec_command is not None and exec_command.get("Command"):
                print(f"[ALERT] Suspicious <Target> found in {file_path} with command: {exec_command.get('Command').strip()}")

        # Check for COMFileReference
        com_file_references = root.findall(".//COMFileReference")
        for com_ref in com_file_references:
            include_attribute = com_ref.get("Include")
            if include_attribute:
                print(f"[ALERT] Suspicious <COMFileReference> found in {file_path}: {include_attribute.strip()}")

        # Check for Imported MSBuild Targets
        imports = root.findall(".//Import")
        for imp in imports:
            project = imp.get("Project")
            if project:
                print(f"[INFO] Imported MSBuild target found in {file_path}: {project.strip()}")

    except ET.ParseError:
        print(f"[ERROR] Failed to parse {file_path}. This file may not be a valid XML project file.")
    except Exception as ex:
        print(f"[ERROR] Failed to scan {file_path}: {str(ex)}")

def check_event(file_path, root, event_name):
    event = root.find(f".//{event_name}")
    if event is not None:
        command = event.find(".//Command")
        if command is not None and command.text:
            print(f"[ALERT] Suspicious <{event_name}> found in {file_path} with command: {command.text.strip()}")

def scan_and_delete_suo_files(directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".suo"):
                suo_path = os.path.join(root, file)
                try:
                    print(f"[WARNING] Potentially malicious .suo file found: {suo_path}")
                    os.remove(suo_path)
                    print(f"[INFO] Deleted {suo_path}")
                except Exception as ex:
                    print(f"[ERROR] Failed to delete {suo_path}: {str(ex)}")
if __name__ == "__main__":
    main()
