import streamlit as st
import os
import zipfile
import re

# Function to search keyword and permissions in XDOZ and SEC files
def search_keyword_in_xdoz_and_sec(parent_folder, keyword, output_file):
    with open(output_file, 'w', encoding='utf-8') as report:
        report.write("File Path, RoleDisplayName, Path, Permissions\n")
        found_any = False  # Flag to check if we found any results
        for root, dirs, files in os.walk(parent_folder):
            for file in files:
                if file.endswith(".xdoz"):
                    xdoz_file_path = os.path.join(root, file)
                    unzip_folder = os.path.join(root, file.replace(".xdoz", ""))
                    os.makedirs(unzip_folder, exist_ok=True)
                    with zipfile.ZipFile(xdoz_file_path, 'r') as zip_ref:
                        zip_ref.extractall(unzip_folder)
                    for dirpath, _, unzipped_files in os.walk(unzip_folder):
                        for unzipped_file in unzipped_files:
                            if unzipped_file.endswith(".xdo") or unzipped_file.endswith(".sec"):
                                file_path = os.path.join(dirpath, unzipped_file)
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    if re.search(keyword, content, re.IGNORECASE):
                                        policies = re.findall(r'<policy.*?roleDisplayName="(.*?)".*?>(.*?)</policy>', content, re.IGNORECASE | re.DOTALL)
                                        for role_display_name, policy_content in policies:
                                            if re.search(keyword, role_display_name, re.IGNORECASE):
                                                permissions_matches = re.findall(r'<folderPermission>.*?<allow path="(.*?)".*?permissions="(.*?)".*?/>.*?</folderPermission>', policy_content, re.IGNORECASE | re.DOTALL)
                                                for path, permissions in permissions_matches:
                                                    permissions_clean = " | ".join([perm.split('.')[-1].capitalize() for perm in permissions.split(',;&#x9;') if perm.strip()])
                                                    report.write(f"{file_path}, {role_display_name}, {path}, {permissions_clean}\n")
                                                    found_any = True  # Mark that we found a result
        if not found_any:
            print("No results found for the given keyword.")
    return output_file

# Function to search keyword in XDMZ and SEC files
def search_keyword_in_xdmz_and_sec(parent_folder, keyword, output_file):
    with open(output_file, 'w', encoding='utf-8') as report:
        report.write("File Path, Line Number, Line\n")
        found_any = False  # Flag to check if we found any results
        for root, dirs, files in os.walk(parent_folder):
            for file in files:
                if file.endswith(".xdmz"):
                    xdmz_file_path = os.path.join(root, file)
                    unzip_folder = os.path.join(root, file.replace(".xdmz", ""))
                    os.makedirs(unzip_folder, exist_ok=True)
                    with zipfile.ZipFile(xdmz_file_path, 'r') as zip_ref:
                        zip_ref.extractall(unzip_folder)
                    for dirpath, _, unzipped_files in os.walk(unzip_folder):
                        for unzipped_file in unzipped_files:
                            if unzipped_file.endswith(".xdm") or unzipped_file.endswith(".sec"):
                                file_path = os.path.join(dirpath, unzipped_file)
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    lines = f.readlines()
                                    for line_num, line in enumerate(lines, 1):
                                        if re.search(keyword, line, re.IGNORECASE):
                                            report.write(f"{file_path}, {line_num}, {line.strip()}\n")
                                            found_any = True  # Mark that we found a result
        if not found_any:
            print("No results found for the given keyword.")
    return output_file

# Streamlit App
st.title("Welcome to Oracle BIP DeepScan")

tab1, tab2 = st.tabs(["Extract Permissions", "Extract SQL Code"])

with tab1:
    st.header("Extract Permissions")
    folder_path = st.text_input("Parent Folder Path", key="folder1")
    keyword = st.text_input("Enter Keyword", key="keyword1")
    if st.button("Search", key="search1"):
        output_file = "keyword_search_report1.csv"
        if folder_path and keyword:
            search_keyword_in_xdoz_and_sec(folder_path, keyword, output_file)
            st.success("Search completed. Download the report:")
            st.download_button(label="Download CSV", data=open(output_file, "r").read(), file_name=output_file, mime="text/csv")
        else:
            st.error("Please provide both the folder path and the keyword.")

with tab2:
    st.header("Extract SQL Code")
    folder_path = st.text_input("Parent Folder Path", key="folder2")
    keyword = st.text_input("Enter Keyword", key="keyword2")
    if st.button("Search", key="search2"):
        output_file = "keyword_search_report2.csv"
        if folder_path and keyword:
            search_keyword_in_xdmz_and_sec(folder_path, keyword, output_file)
            st.success("Search completed. Download the report:")
