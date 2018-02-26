#!/usr/bin/env python

import pycurl, json, glob
from io import BytesIO

'''
Script to automate MobSF's API operations.  This code currently accepts no arguments.
All malware files (.APK extension) must be put inside the same directory as the code itself.
The user has the option to not delete scans.  This allows him to further check results
on the web interface.
'''

# Building the Base URL.
base = input("Type the full URL of MobSF, including port. (No trailing slash): ").strip()
base += "/api/v1/"

key = input("Type the current API key: ").strip()
delete = input("DELETE the scans? Only y or Y will be considered a positive answer: ").strip()
delete = delete.upper()

# Operations to make with the API
operations = ["upload", "scan", "download_pdf"]
if delete == "Y":
  operations.append("delete_scan")

# Listing .API files located in the same directory.
files = sorted(glob.glob("*.apk"))
total_files = len(files)
position = 1
print()

for file in files:
  print("Processing file %d of %d..." % (position, total_files))
  for operation in operations:
    buffer = BytesIO()
    url = base + operation
    c = pycurl.Curl()
    c.setopt(c.URL, url)
    c.setopt(c.POST, 1)
    c.setopt(pycurl.HTTPHEADER, ['Authorization:' + key])
    c.setopt(c.WRITEDATA, buffer)
    print("Running %s of %s file..." % (operation, file))
    if operation == "upload":
      c.setopt(c.HTTPPOST, [("file", (c.FORM_FILE, file))])
      c.perform()
      body = buffer.getvalue()
      result = json.loads(body.decode('iso-8859-1'))
      code = result["hash"]
    elif operation == "scan":
      c.setopt(c.POSTFIELDS, "scan_type=apk&file_name=" + file + "&hash=" + code)
      c.perform()
    elif operation == "download_pdf":
      file_pdf = file.replace("apk", "pdf")
      c.setopt(c.POSTFIELDS, "hash=" + code + "&scan_type=apk")
      c.perform()
      body = buffer.getvalue()
      f = open(file_pdf, "wb")
      f.write(body)
      f.close()
    elif operation == "delete_scan":
      c.setopt(c.POSTFIELDS, "hash=" + code)
      c.perform()
    c.close()
  print("------------------------------------------------------------------")
  position += 1
print("End of Processing.")
