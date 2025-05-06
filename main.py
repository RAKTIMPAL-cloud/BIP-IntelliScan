import streamlit as st
import os
import zipfile
import re
import shutil
from PIL import Image
import requests
from io import BytesIO

# Page setup
st.set_page_config(page_title="Oracle BIP IntelliScan Tool", page_icon="🔍")

# Display a single image with fixed size

# URL of the image to be displayed
img_url = "https://img.freepik.com/premium-vector/chatbot-icon-concept-chat-bot-chatterbot-robot-virtual-assistance-website_123447-1509.jpg"

# Fetch the image from the URL
response = requests.get(img_url)
img = Image.open(BytesIO(response.content))

# Resize the image to a desired smaller size
img = img.resize((800, 340))  # Resize image to 150x150 pixels

# Custom CSS styling
st.markdown("""
    <style>
        .stApp {
            background-color: #9cbbf9;
            color: #ffffff;
            font-family: Arial, sans-serif;
        }
        .custom-header {
            font-size: 2.5em;
            color: #050131;
            text-align: center;
            margin-top: 10px;
            font-weight: bold;
        }
        .custom-box {
            background-color: #050131;
            padding: 15px;
            border-radius: 12px;
            box-shadow: 2px 2px 12px rgba(0, 0, 0, 0.5);
            color: #ffffff;
        }
        .stButton>button {
            background-color: #050131;
            color: #ffffff;
            border: none;
            padding: 8px 20px;
            font-size: 1em;
            font-weight: bold;
            border-radius: 8px;
            cursor: pointer;
        }
        .stButton>button:hover {
            background-color: #061175;
        }
    </style>
    """, unsafe_allow_html=True)

# Center the image above the header
st.image(img)  # Display the resized image

# Title and tabs
st.markdown('<div class="custom-header">Oracle BIP Reports IntelliScan Tool</div>', unsafe_allow_html=True)

# Add the hyperlink just below the title
st.markdown("""
<div style='font-size: 20px; margin-bottom: 20px;'>
    🔗 For scanning custom objects (Lookups, Fast Formulas, Value Sets), 
    <a href='https://oracle-hcm-custom-objects-intelliscan.streamlit.app/' target='_blank' style='color: yellow; font-weight: bold; text-decoration: underline;'>
        click here
    </a>
</div>
""", unsafe_allow_html=True)

tab1, tab2 = st.tabs(["Extract Report's Permissions", "Keyword Finder in Data Model"])

# Temp directory for extracted files
temp_dir = "temp_dir"
os.makedirs(temp_dir, exist_ok=True)

# Function to unzip .xdrz files and process internal .xdoz/.xdmz files
def extract_xdrz(file, extract_to):
    with zipfile.ZipFile(file, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

# Adjusted Function to search keyword and permissions in XDOZ and SEC files within XDOZ folders
def search_keyword_in_xdoz_and_sec(folder, keyword, output_file):
    with open(output_file, 'w', encoding='utf-8') as report:
        report.write("File Path, RoleDisplayName, Path, Permissions\n")
        found_any = False
        for root, dirs, files in os.walk(folder):
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
                                                # Adjusted to correctly capture permissions without '&#x9;' characters
                                                permissions_matches = re.findall(
                                                    r'<folderPermission>.*?<allow path="(.*?)".*?permissions="(.*?)".*?/>.*?</folderPermission>',
                                                    policy_content, re.IGNORECASE | re.DOTALL
                                                )
                                                for path, permissions in permissions_matches:
                                                    # Clean up and format permissions
                                                    permissions_clean = " | ".join(
                                                        [perm.split('.')[-1].capitalize() for perm in re.split(r'[,\s;]+', permissions) if perm.strip() and "&#x9" not in perm]
                                                    )
                                                    report.write(f"{file_path}, {role_display_name}, {path}, {permissions_clean}\n")
                                                    found_any = True
        if not found_any:
            st.warning("No results found for the given keyword.")
    return output_file

# Function to search keyword in XDMZ and SEC files
def search_keyword_in_xdmz_and_sec(folder, keyword, output_file):
    with open(output_file, 'w', encoding='utf-8') as report:
        report.write("File Path, Line Number, Line\n")
        found_any = False
        for root, dirs, files in os.walk(folder):
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
                                            found_any = True
        if not found_any:
            st.warning("No results found for the given keyword.")
    return output_file

with tab1:
    st.header("Extract Permissions")
    uploaded_files = st.file_uploader("Upload .xdrz files", type="xdrz", accept_multiple_files=True, key="permissions")
    keyword_permissions = st.text_input("Enter Keyword", key="keyword_permissions")
    if st.button("Search", key="search_permissions"):
        output_file = "keyword_search_report_permissions.csv"
        if uploaded_files and keyword_permissions:
            for uploaded_file in uploaded_files:
                xdrz_path = os.path.join(temp_dir, uploaded_file.name)
                with open(xdrz_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                extract_xdrz(xdrz_path, temp_dir)
                search_keyword_in_xdoz_and_sec(temp_dir, keyword_permissions, output_file)
            st.success("Search completed. Download the report:")
            st.download_button(label="Download CSV", data=open(output_file, "r").read(), file_name=output_file, mime="text/csv")
        else:
            st.error("Please upload files and provide the keyword.")

with tab2:
    st.header("Keyword Finder")
    uploaded_files_sql = st.file_uploader("Upload .xdrz files", type="xdrz", accept_multiple_files=True, key="sql_code")
    keyword_sql = st.text_input("Enter Keyword", key="keyword_sql")
    if st.button("Search", key="search_sql"):
        output_file = "keyword_search_report_sql.csv"
        if uploaded_files_sql and keyword_sql:
            for uploaded_file in uploaded_files_sql:
                xdrz_path = os.path.join(temp_dir, uploaded_file.name)
                with open(xdrz_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                extract_xdrz(xdrz_path, temp_dir)
                search_keyword_in_xdmz_and_sec(temp_dir, keyword_sql, output_file)
            st.success("Search completed. Download the report:")
            st.download_button(label="Download CSV", data=open(output_file, "r").read(), file_name=output_file, mime="text/csv")
        else:
            st.error("Please upload files and provide the keyword.")

# Clean up temp directory after the search
shutil.rmtree(temp_dir, ignore_errors=True)

st.markdown("""
<hr style="margin-top: 50px;">
<div style='text-align: center; color: yellow; font-size: 0.85em;'>
    <p>App has been developed by <strong>Raktim Pal</strong></p>
    <p>© 2025 Raktim Pal. All rights reserved.</p>
</div>
""", unsafe_allow_html=True)
