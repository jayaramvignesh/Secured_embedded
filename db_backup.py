import os
from subprocess import Popen

#user = "vjayaram"
#password = "vjayaram"
#db = "vjayaram"
#host = "localhost"
#op = "db_bcakup"

#os.popen("mysqldump -u %s -p%s -h %s -e --opt -c %s | gzip -c > %s.gz"%(user,password,host,db,op)) 

f = open("backup.sql", "w")
x = Popen(["mysqldump","-u","vjayaram","-pvjayaram","vjayaram"],stdout = f)
x.wait()
f.close()

