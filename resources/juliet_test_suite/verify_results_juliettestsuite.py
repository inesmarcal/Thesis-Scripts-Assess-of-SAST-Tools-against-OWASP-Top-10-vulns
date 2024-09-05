from xml.dom import minidom
import re, copy
import itertools

class File_count_juliet_test:
    def __init__(self, name, typ=""):
        self.name = name
        self.marked = 0
        self.kiuwan_marked = 0
        self.typ = typ
        self.BypassAuthorization = 0 
        self.ErrorHandling = 0
        self.HardCodedPass = 0
        self.HardConstant = 0
        self.Hash = 0
        self.HttpSplitting = 0
        self.LDAP = 0
        self.LogOutputNeutralization = 0
        self.ObsoleteFunctions = 0
        self.OS_CommandInjection = 0
        self.Path_Transversal = 0
        self.SameSeed = 0
        self.SensitiveCookieWithoutSecure = 0
        self.SessionExpiration = 0
        self.SQLInjection = 0
        self.Weak_PRNG = 0
        self.WeakCrypto = 0
        self.XPath = 0
        self.XSS = 0
        self.dic = {"BypassAuthorization": [0,0,0,0], "ErrorHandling": [0,0,0,0], "HardCodedPass": [0,0,0,0], "HardConstant": [0,0,0,0], "Hash": [0,0,0,0], 
                    "HttpSplitting": [0,0,0,0], "LDAP": [0,0,0,0], "LogOutputNeutralization": [0,0,0,0], "ObsoleteFunctions": [0,0,0,0], 
                    "OS_CommandInjection": [0,0,0,0], "Path_Transversal": [0,0,0,0], "SameSeed": [0,0,0,0], "SensitiveCookieWithoutSecure": [0,0,0,0],
                    "SessionExpiration": [0,0,0,0], "SQLInjection": [0,0,0,0], "Weak_PRNG": [0,0,0,0], "WeakCrypto": [0,0,0,0], "XPath": [0,0,0,0], "XSS": [0,0,0,0], }
                    #[tp, fn, fp]

        self.line = {"BypassAuthorization": [0], "ErrorHandling": [0], "HardCodedPass": [0], "HardConstant": [0], "Hash": [0], 
                    "HttpSplitting": [0], "LDAP": [0], "LogOutputNeutralization": [0], "ObsoleteFunctions": [0], 
                    "OS_CommandInjection": [0], "Path_Transversal": [0], "SameSeed": [0], "SensitiveCookieWithoutSecure": [0], 
                    "SessionExpiration": [0], "SQLInjection": [0], "Weak_PRNG": [0], "WeakCrypto": [0], "XPath": [0], "XSS": [0], }
        self.versions = {}

    def incr(self, name, n=1):
        setattr(self, name, getattr(self, name)+n)

    def __str__(self):
        return self.name + "/" + str(self.versions)
        #return self.name + "/" + str(self.line)

        '''return "How many was detected in " + self.name + ":\n" +\
            "cmdi: " + str(self.cmdi) + "\n" +\
            "crypto: " + str(self.crypto) + "\n" +\
            "hash: " + str(self.hash) + "\n" +\
            "ldapi: " + str(self.ldapi) + "\n" +\
            "pathtraver: " + str(self.pathtraver) + "\n" +\
            "securecookie: " + str(self.securecookie) + "\n" +\
            "sqli: " + str(self.sqli) + "\n" +\
            "trustbound: " + str(self.trustbound) + "\n" +\
            "weakrand: " + str(self.weakrand) + "\n" +\
            "xpathi: " + str(self.xpathi) + "\n" +\
            "xss: " + str(self.xss) + "\n"'''

    def set_line(self, vuln, line):
        self.line[vuln].append(line)

    def compare(self, another):
        attrs = ["BypassAuthorization", "ErrorHandling", "HardCodedPass", "HardConstant", "Hash", 
                    "HttpSplitting", "LDAP", "LogOutputNeutralization", "ObsoleteFunctions", 
                    "OS_CommandInjection", "Path_Transversal", "SameSeed",  "SensitiveCookieWithoutSecure",
                    "SessionExpiration", "SQLInjection", "Weak_PRNG", "WeakCrypto", "XPath", "XSS"] 
        
        for attr in attrs:
            if self.line[attr][0] == 0:
                if another.line[attr][0] != 0:
                    self.dic[attr][2] += 1
            else:
                if another.line[attr][0] != 0:
                    for l in another.line[attr]:
                        if l < self.line[attr][0]:
                            self.dic[attr][0] += 1 if self.marked == 0 else 0
                            self.marked = 1
                        else:
                            self.dic[attr][2] += 1
                else:
                    self.dic[attr][1] += 1

    def compare2(self, another, tool=""):
        attrs = ["BypassAuthorization", "ErrorHandling", "HardCodedPass", "HardConstant", "Hash", 
                    "HttpSplitting", "LDAP", "LogOutputNeutralization", "ObsoleteFunctions", 
                    "OS_CommandInjection", "Path_Transversal", "SameSeed",  "SensitiveCookieWithoutSecure",
                    "SessionExpiration", "SQLInjection", "Weak_PRNG", "WeakCrypto", "XPath", "XSS"] 
        for k in self.versions.keys():
            if k in another.versions:
                if type(self.versions[k]) is str:
                    #print(self.versions[k], k)
                    pass
                    '''if(re.search("_bad", k)):
                        self.dic[self.versions[k]][0] += 1 if self.marked == 0 else 0
                        self.marked = 1
                    if(re.search("_good", k)):
                        self.dic[self.versions[k]][2] += 1'''
                else:
                    #print(self.versions[k], k)
                    for attr in attrs:
                        #if attr == "SQLInjection" and self.typ == "SQLInjection":
                        #    print(another.versions[k][attr], "######", self.versions[k][attr][0])
                        if self.versions[k][attr][0] == 0:
                            if another.versions[k][attr][0] != 0:
                                self.dic[attr][2] += len(another.versions[k][attr])
                                self.dic[attr][3] += len(another.versions[k][attr])
                                self.kiuwan_marked += 1
                        else:
                            if another.versions[k][attr][0] != 0:
                                for l in another.versions[k][attr]:
                                    if l < self.versions[k][attr][0]:
                                        self.dic[attr][0] += 1 if self.marked == 0 else 0
                                        self.marked = 1
                                    else:
                                        self.dic[attr][2] += 1
                                    self.kiuwan_marked += 1
                            else:
                                pass
                                #self.dic[attr][1] += 1
        
        if self.marked == 0:
            self.dic[self.typ][1] += 1


def spotbugs(dic):
     #Vulnerabilities that are not cookies
    f_juliet = open("expect_test_cases_list/expected.txt", "r")
    f_spotbugs = minidom.parse("tools_result/res_spotbugs.xml")
    models = f_spotbugs.getElementsByTagName('BugInstance')
    vulns = ["COMMAND_INJECTION", #0
            "CIPHER_INTEGRITY", #1
            "HTTPONLY_COOKIE", #2
            "INSECURE_COOKIE", #3
            "XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER", #4
            "XSS_REQUEST_PARAMETER_TO_SEND_ERROR", #5
            "DES_USAGE", #6
            "TDES_USAGE", #7
            "DMI_CONSTANT_DB_PASSWORD", #8
            "ECB_MODE", #9
            "HTTP_RESPONSE_SPLITTING", #10
            "HRS_REQUEST_PARAMETER_TO_COOKIE", #11
            "HRS_REQUEST_PARAMETER_TO_HTTP_HEADER", #12
            "HARD_CODE_PASSWORD", #13
            "HARD_CODE_KEY", #14 
            "INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE", #15
            "LDAP_INJECTION", #16
            "WEAK_MESSAGE_DIGEST_MD5", #17
            "PT_ABSOLUTE_PATH_TRAVERSAL", #18
            "PT_RELATIVE_PATH_TRAVERSAL", #19
            "PATH_TRAVERSAL_IN", #20
            "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE", #21
            "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING", #22
            "PREDICTABLE_RANDOM", #23
            "WEAK_MESSAGE_DIGEST_SHA1", #24
            "SQL_INJECTION_JDBC", #25
            "UNVALIDATED_REDIRECT", #26
            "XPATH_INJECTION"] #27

    mapping_benchmark_owasp = {"BypassAuthorization":[vulns[26]],  "ErrorHandling": [], "HardCodedPass": [vulns[8], vulns[13]], "HardConstant": [vulns[14]], 
                                "Hash": [vulns[17], vulns[24]], "HttpSplitting": [vulns[10], vulns[11], vulns[12]], "LDAP": [vulns[16]], "LogOutputNeutralization": [vulns[15]],
                                "ObsoleteFunctions": [], "OS_CommandInjection": [vulns[0]], "Path_Transversal": [vulns[18], vulns[19], vulns[20]], "SameSeed": [],
                                "SensitiveCookieWithoutSecure": [vulns[3]], "SessionExpiration": [], "SQLInjection": [vulns[21], vulns[22], vulns[25]],
                                "Weak_PRNG": [vulns[23]], "WeakCrypto": [vulns[1], vulns[6], vulns[7], vulns[9]], "XPath": [vulns[27]], "XSS": [vulns[4], vulns[5]]}
    
    list_juliet = {}
    list_spotbugs = {}
    line_atual = ""
    lines_left = 0

    for l in f_juliet.readlines():
        l_splited = l.split(",")
        #print(l_splited[0])
        if lines_left == 0:
            lines_left = int(l_splited[0])
            aux = File_count_juliet_test(l_splited[1], l_splited[2])
            list_spotbugs[l_splited[1]] = File_count_juliet_test(l_splited[1], l_splited[2])
            aux.incr(l_splited[2])
            list_juliet[l_splited[1]] = aux
        else:
            if len(l_splited) == 5:
                #list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line[l_splited[1]][0] =
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]][l_splited[1]][0] = int(l_splited[3]) 
            else:
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = l_splited[1]

            lines_left -= 1
    
    #for k, v in list_juliet.items():
    #    print(k, v.versions)
    
    for elem in models:
        indexxx = -1
        while(len(elem.getElementsByTagName('SourceLine')) != -indexxx and ("sourcefile" not in elem.getElementsByTagName('SourceLine')[indexxx].attributes or elem.getElementsByTagName('SourceLine')[indexxx].attributes['sourcefile'].value[:3] != "CWE")):
            indexxx -= 1

        if "start" not in elem.getElementsByTagName('SourceLine')[indexxx].attributes:
            continue
        
        name = elem.getElementsByTagName('SourceLine')[indexxx].attributes['sourcefile'].value
        line = elem.getElementsByTagName('SourceLine')[indexxx].attributes['start'].value

        if name[:3] != "CWE":
            print(name, elem.attributes['type'].value)

        if elem.attributes['category'].value == "SECURITY" and elem.attributes['type'].value in vulns and name[:3] == "CWE":
            name2 = re.sub(r"(_bad|_goodG2B|_base|a|b|c|d|e|)[.]java","",name)
            name = name[:-5]
            
            for k, v in mapping_benchmark_owasp.items():
                if elem.attributes['type'].value in v:
                    list_spotbugs[name2].incr(k)
                    if name in list_spotbugs[name2].versions:
                        if list_spotbugs[name2].versions[name][k][0] != 0:
                            list_spotbugs[name2].versions[name][k].append(int(line))
                        else:
                            list_spotbugs[name2].versions[name][k][0] = int(line)
                        #print(1, list_spotbugs[name2].versions[name][k], attr_atual)
                    else:
                        list_spotbugs[name2].versions[name] = list_spotbugs[name2].line
                        list_spotbugs[name2].versions[name][k][0] = int(line)
                        #print(2, list_spotbugs[name2].versions[name][k], attr_atual)
                    break

    empty = File_count_juliet_test("none")
    for k, v in list_juliet.items():
        if k in list_spotbugs:
            list_juliet[k].compare2(list_spotbugs[k])
        else:
            list_juliet[k].compare2(empty)

    for v in list_juliet.values():
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]
    
    return dic, list_juliet

def fortify(dic):
    f_juliet = open("expect_test_cases_list/expected.txt", "r")
    f_fortify = open("tools_result/res_fortify.txt", "r")

    vulns = ["Access Control: Database", #0
            "Command Injection", #1
            "Cookie Security: Persistent Cookie", #2
            "Cookie Security: Cookie not Sent Over SSL", #3
            "Cross-Site Scripting: Reflected", #4
            "Header Manipulation", #5
            "Header Manipulation: Cookies", #6
            "Insecure Randomness", #7 
            "LDAP Injection", #8 
            "Missing Check against Null", #9
            "Obsolete", #10
            "Password Management", #11 
            "Password Management: Hardcoded Password", #12
            "Path Manipulation", #13 
            "Poor Error Handling: Empty Catch Block", #14 
            "Poor Error Handling: Program Catches NullPointerException", #15
            "SQL Injection", #16 
            "Weak Cryptographic Hash", #17 
            "Weak Encryption", #18 
            "Weak Encryption: Insufficient Key Size", #19
            "XPath Injection",#20
            "Cross-Site Scripting: Persistent"] 

    mapping_benchmark_owasp = {"BypassAuthorization":[vulns[0]],  "ErrorHandling": [vulns[9], vulns[14], vulns[15]], "HardCodedPass": [vulns[11], vulns[12]], "HardConstant": [], 
                                "Hash": [vulns[17]], "HttpSplitting": [vulns[5], vulns[6]], "LDAP": [vulns[8]], "LogOutputNeutralization": [],
                                "ObsoleteFunctions": [vulns[10]], "OS_CommandInjection": [vulns[1]], "Path_Transversal": [vulns[13]], "SameSeed": [], 
                                "SensitiveCookieWithoutSecure": [vulns[3]], "SessionExpiration": [vulns[2]], "SQLInjection": [vulns[16]],
                                "Weak_PRNG": [vulns[7]], "WeakCrypto": [vulns[18], vulns[19]], "XPath": [vulns[20]], "XSS": [vulns[4], vulns[21]]}

    list_juliet = {}
    list_fortify = {}
    line_atual = ""
    lines_left = 0

    for l in f_juliet.readlines():
        l_splited = l.split(",")
        #print(l_splited[0])
        if lines_left == 0:
            lines_left = int(l_splited[0])
            aux = File_count_juliet_test(l_splited[1], l_splited[2])
            list_fortify[l_splited[1]] = File_count_juliet_test(l_splited[1], l_splited[2])
            aux.incr(l_splited[2])
            list_juliet[l_splited[1]] = aux
        else:
            if len(l_splited) == 5:
                n = re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]
                list_juliet[n].versions[n] = list_juliet[n].line
                list_juliet[n].versions[n][l_splited[1]][0] = int(l_splited[3]) 
            lines_left -= 1

    for l in f_fortify.readlines():
        if l != line_atual:
            if l[1] == "\"":
                attr_atual = l.split("\"")[1]
            else:
                if attr_atual in vulns:
                    name = name2 = l.split("/")[-1].split(" ")[0].split(":")[0][:-5]
                    line = l.split("/")[-1].split(" ")[0].split(":")[1]
                    for k, v in mapping_benchmark_owasp.items():
                        if attr_atual in v:
                            #print(name, attr_atual, line)
                            list_fortify[name].incr(k)
                            if name in list_fortify[name2].versions:
                                if list_fortify[name2].versions[name][k][0] != 0:
                                    list_fortify[name2].versions[name][k].append(int(line))
                                else:
                                    list_fortify[name2].versions[name][k][0] = int(line)
                                #print(1, list_fortify[name2].versions[name][k], attr_atual)
                            else:
                                list_fortify[name2].versions[name] = list_fortify[name2].line
                                list_fortify[name2].versions[name][k][0] = int(line)
                                #print(2, list_fortify[name2].versions[name][k], attr_atual)
                            break
            line_atual = l

    empty = File_count_juliet_test("none")
    for k, v in list_juliet.items():
        if k in list_fortify:
            list_juliet[k].compare2(list_fortify[k])
        else:
            list_juliet[k].compare2(empty)

    for v in list_juliet.values():
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]
    
    return dic, list_juliet
    
def semgrep(dic):
    f_juliet = open("expect_test_cases_list/expected.txt", "r")
    f_semgrep = open("tools_result/res_semgrep.txt", "r")

    vulns = ["sqli", #0
             "path-transversal", #1
             "hardcoded-pass", #2
             "ldapi", #3
             "xpathi", #4
             "cmd", #5
             "insecure-algorithm", #6
             "xss", #7
             "output-neutralization", #8
             "bypass-auth", #9
             "hash", #10
             "object-deserialization", #11
             "hardcoded-secret", #12 
             "cookie-missing-secure-flag" #13
            ]
    
    mapping_benchmark_owasp = {"BypassAuthorization":[vulns[9]],  "ErrorHandling": [], "HardCodedPass": [vulns[2]], "HardConstant": [vulns[12]], 
                                "Hash": [vulns[10]], "HttpSplitting": [], "LDAP": [vulns[3]], "LogOutputNeutralization": [vulns[8]],
                                "ObsoleteFunctions": [], "OS_CommandInjection": [vulns[5]], "Path_Transversal": [vulns[1]], "SameSeed": [], 
                                "SessionExpiration": [], "SQLInjection": [vulns[0]], "SensitiveCookieWithoutSecure": [vulns[13]],
                                "Weak_PRNG": [], "WeakCrypto": [vulns[6]], "XPath": [vulns[4]], "XSS": [vulns[7]]}

    list_juliet = {}
    list_semgrep = {}
    line_atual = ""
    lines_left = 0

    lines = f_semgrep.readlines()
    next_line = 0

    for l in f_juliet.readlines():
        l_splited = l.split(",")
        #print(l_splited[0])
        if lines_left == 0:
            lines_left = int(l_splited[0])
            aux = File_count_juliet_test(l_splited[1], l_splited[2])
            list_semgrep[l_splited[1]] = File_count_juliet_test(l_splited[1], l_splited[2])
            aux.incr(l_splited[2])
            list_juliet[l_splited[1]] = aux
        else:
            if len(l_splited) == 5:
                #list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line[l_splited[1]][0] =
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]][l_splited[1]][0] = int(l_splited[3]) 
            else:
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = l_splited[1]
            
            lines_left -= 1
    
    for i in range(len(lines)):
        if next_line == i:
            if(lines[i].split("\n")[0] != "3d"):
                next_line += 1
                attr_atual = lines[i].split("\n")[0]
                #print(attr_atual)
            else: 
                next_line += 6
                name = lines[i+1].split("/")[-1].split(":")[0]
                line = int(lines[i+1].split("/")[-1].split(":")[1])
                name2 = re.sub(r"(_bad|_goodG2B|_base|a|b|c|d|e|)[.]java","",name)
                name = name[:-5]
                for k, v in mapping_benchmark_owasp.items():
                    if attr_atual in v:
                        if name in list_semgrep[name2].versions:
                            if list_semgrep[name2].versions[name][k][0] != 0:
                                list_semgrep[name2].versions[name][k].append(int(line))
                            else:
                                list_semgrep[name2].versions[name][k][0] = int(line)
                            #print(1, list_semgrep[name2].versions[name][k], attr_atual)
                        else:
                            list_semgrep[name2].versions[name] = list_semgrep[name2].line
                            list_semgrep[name2].versions[name][k][0] = int(line)
                            #print(2, list_semgrep[name2].versions[name][k], attr_atual)
    
   

    empty = File_count_juliet_test("none")
    for k, v in list_juliet.items():
        if k in list_semgrep:
            list_juliet[k].compare2(list_semgrep[k])
        else:
            list_juliet[k].compare2(empty)
    

    for v in list_juliet.values():
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_juliet

def synopsys(dic):
    f_juliet = open("expect_test_cases_list/expected.txt", "r")
    f_synopsys = open("tools_result/res_synopsys.csv", "r")

    vulns = ["Unspecified Cipher Transformation", #0
            "LDAP injection", #1
            "SQL injection", #2
            "LDAP anonymous authentication", #3
            "XML Path (XPath) Language injection", #4
            "OS Command Injection", #5
            "Filesystem path", #6
            "Weak hash algorithm", #7
            "Insufficient Symmetric Key Size", #8
            "Use of hard-coded password", #9
            "Risky cryptographic function", #10
            "Excessive session lifetime", #11
            "Open redirect", #12
            "Use of hard-coded cryptographic key", #13
            "Constant seed used in random number generator", #14
            "Cross-site scripting", #15
            "Risky cryptographic hashing function", #16
            "HttpOnly attribute not set for cookie", #17
            "Missing or insecure samesite attribute for cookie"
            ] 
    
    mapping_benchmark_owasp = {"BypassAuthorization":[vulns[12]],  "ErrorHandling": [], "HardCodedPass": [vulns[9]], "HardConstant": [vulns[13]], 
                                "Hash": [vulns[7]], "HttpSplitting": [], "LDAP": [vulns[1], vulns[3]], "LogOutputNeutralization": [],
                                "ObsoleteFunctions": [], "OS_CommandInjection": [vulns[5]], "Path_Transversal": [vulns[6]], "SameSeed": [vulns[14]], 
                                "SessionExpiration": [vulns[11],], "SQLInjection": [vulns[2]], "SensitiveCookieWithoutSecure": [],
                                "Weak_PRNG": [], "WeakCrypto": [vulns[0], vulns[8], vulns[10], vulns[16]], "XPath": [vulns[4]], "XSS": [vulns[15]]}


    list_juliet = {}
    list_synopsys = {}
    line_atual = ""
    lines_left = 0

    attr_atual = ""

    for l in f_juliet.readlines():
        l_splited = l.split(",")
        #print(l_splited[0])
        if lines_left == 0:
            lines_left = int(l_splited[0])
            aux = File_count_juliet_test(l_splited[1], l_splited[2])
            list_synopsys[l_splited[1]] = File_count_juliet_test(l_splited[1], l_splited[2])
            aux.incr(l_splited[2])
            list_juliet[l_splited[1]] = aux
        else:
            if len(l_splited) == 5:
                #list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line[l_splited[1]][0] =
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]][l_splited[1]][0] = int(l_splited[3]) 
            else:
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = l_splited[1]
            
            lines_left -= 1

    
    for l in f_synopsys.readlines():
        l = l.split(",")
        attr_atual = l[1]
        #print(attr_atual)
        #print(l)
        if l[-1][:-1] == "Various":
            continue

        name = l[-3].split("/")[-1].split(".")[0]+".java"
        line = int(l[-1])
        name2 = re.sub(r"(_bad|_goodG2B|_base|a|b|c|d|e|)[.]java","", name)
        name = name = name[:-5]
        if re.search(r"CWE.*",name) and attr_atual in vulns:
            for k, v in mapping_benchmark_owasp.items():
                if attr_atual in v:
                    if name in list_synopsys[name2].versions:
                        if list_synopsys[name2].versions[name][k][0] != 0:
                            list_synopsys[name2].versions[name][k].append(int(line))
                        else:
                            list_synopsys[name2].versions[name][k][0] = int(line)
                        #print(1, list_synopsys[name2].versions[name][k], attr_atual)
                    else:
                        list_synopsys[name2].versions[name] = list_synopsys[name2].line
                        list_synopsys[name2].versions[name][k][0] = int(line)
                        #print(2, list_synopsys[name2].versions[name][k], attr_atual)
                    break
    
    empty = File_count_juliet_test("none")
    for k, v in list_juliet.items():
        if k in list_synopsys:
            list_juliet[k].compare2(list_synopsys[k])
        else:
            list_juliet[k].compare2(empty)

    for v in list_juliet.values():
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]
    
    return dic, list_juliet

def kiuwaaaan(dic):
    f_juliet = open("expect_test_cases_list/expected.txt", "r")
    f_kiuwaaaan = open("tools_result/res_kiuwaaaan.csv", "r")

    vulns = ["URL Redirection to Untrusted Site ('Open Redirect')", #0
            "Avoid Exception, RuntimeException o Throwable in catch or throw statements", #1
            "Avoid sensitive information exposure through error messages", #2
            "Avoid throwing java.lang.Error", #3
            "Avoid capturing NullPointerExceptions", #4
            "Avoid creating new instances of java.lang.Exception", #5
            "Avoid java.lang.Error catch exceptions", #6
            "Use of Hard-coded Credentials", #7
            "Hardcoded cryptographic keys", #8
            "Weak cryptographic hash", #9
            "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')", #10
            "Do not use the printStackTrace method", #11
            "Standard pseudo-random number generators cannot withstand cryptographic attacks", #12
            "Weak symmetric encryption algorithm", #13
            "Improper Neutralization of Data within XPath Expressions ('XPath Injection')", #14
            "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", #15
            "Avoid non-neutralized user-controlled input in LDAP search filters", #16
            "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", #17
            "Avoid non-neutralized user-controlled input composed in a pathname to a resource", #18
            "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", #19
            "Always normalize system inputs", #20
            "Incorrect Behavior Order: Validate Before Canonicalize", #21
            "Use PreparedStatement instead of Statement to similar requests"] #22 
    
    mapping_benchmark_owasp = {"BypassAuthorization":[vulns[0], ],  "ErrorHandling": [vulns[1], vulns[3], vulns[4], vulns[5], vulns[6], ], "HardCodedPass": [vulns[7], ], "HardConstant": [vulns[8], ], 
                                "Hash": [vulns[9], ], "HttpSplitting": [vulns[10], ], "LDAP": [vulns[16],], "LogOutputNeutralization": [vulns[2], vulns[11], ],
                                "ObsoleteFunctions": [], "OS_CommandInjection": [vulns[17],], "Path_Transversal": [vulns[18], vulns[20], vulns[21]], "SameSeed": [], 
                                "SessionExpiration": [], "SQLInjection": [vulns[19], vulns[22]], "SensitiveCookieWithoutSecure": [],
                                "Weak_PRNG": [vulns[12], ], "WeakCrypto": [vulns[13], ], "XPath": [vulns[14], ], "XSS": [vulns[15], ]}


    list_juliet = {}
    list_kiuwaaaan = {}
    line_atual = ""
    lines_left = 0

    attr_atual = ""

    for l in f_juliet.readlines():
        l_splited = l.split(",")
        #print(l_splited[0])
        if lines_left == 0:
            lines_left = int(l_splited[0])
            aux = File_count_juliet_test(l_splited[1], l_splited[2])
            list_kiuwaaaan[l_splited[1]] = File_count_juliet_test(l_splited[1], l_splited[2])
            aux.incr(l_splited[2])
            list_juliet[l_splited[1]] = aux
        else:
            if len(l_splited) == 5:
                #list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line[l_splited[1]][0] =
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]][l_splited[1]][0] = int(l_splited[3]) 
            else:
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = l_splited[1]
            
            lines_left -= 1

    for l in f_kiuwaaaan.readlines():
        l = l.split(",")
        attr_atual = l[1]
        #print(attr_atual)
        #print(l)
        indexxx = 6
        if re.search("[0-9]+m", l[6]) :
            indexxx = 7

        if l[indexxx+1] == "":
            continue

        #print(l[indexxx], indexxx, l[indexxx+1])
        name = l[indexxx].split("/")[1].split(".")[0]+".java" if "/" in l[indexxx] else l[indexxx]
        line = int(l[indexxx+1])
        name2 = re.sub(r"(_bad|_goodG2B|_base|a|b|c|d|e|)[.]java","", name)
        name = name[:-5]
        
        if re.search(r"CWE.*",name) and attr_atual in vulns:
            for k, v in mapping_benchmark_owasp.items():
                if attr_atual in v:
                    list_kiuwaaaan[name2].incr(k)
                    if name in list_kiuwaaaan[name2].versions:
                        if list_kiuwaaaan[name2].versions[name][k][0] != 0:
                            list_kiuwaaaan[name2].versions[name][k].append(int(line))
                        else:
                            list_kiuwaaaan[name2].versions[name][k][0] = int(line)
                        #print(1, list_kiuwaaaan[name2].versions[name][k], attr_atual)
                    else:
                        list_kiuwaaaan[name2].versions[name] = list_kiuwaaaan[name2].line
                        list_kiuwaaaan[name2].versions[name][k][0] = int(line)
                        #print(2, list_kiuwaaaan[name2].versions[name][k], attr_atual)
                    break

    empty = File_count_juliet_test("none")
    for k, v in list_juliet.items():
        if k in list_kiuwaaaan:
            list_juliet[k].compare2(list_kiuwaaaan[k], "kiuwan")
        else:
            list_juliet[k].compare2(empty, "kiuwan")

    for v in list_juliet.values():
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_juliet

def horusec(dic):
    f_juliet = open("expect_test_cases_list/expected.txt", "r")
    f_horusec = open("tools_result/res_horusec.txt", "r")

    vulns = ["Potential Hard-coded credential", #0
             "Weak Cryptographic Hash Function used", #1
             "SQL Injection", #2
             "SQL Injection With Turbine", #3
             "SQL Injection JDBC", #4
             "Weak block mode for Cryptographic Hash Function", #5
             " Crypto import", #6
             "SecureRandom seeds should not be predictable", #7
             "Potential LDAP Injection", #8
             "Insecure Random Number Generator", #9
             "Potential XSS in Servlet", #10 
             "Execute OS Command", #11
             "No Log Sensitive Information", #12
             "DES, DESede, RSA is insecure"] #13 
    
    mapping_benchmark_owasp = {"BypassAuthorization":[],  "ErrorHandling": [], "HardCodedPass": [vulns[0], ], "HardConstant": [], 
                                "Hash": [vulns[1], ], "HttpSplitting": [], "LDAP": [vulns[8], ], "LogOutputNeutralization": [vulns[12], ],
                                "ObsoleteFunctions": [], "OS_CommandInjection": [vulns[11], ], "Path_Transversal": [], "SameSeed": [vulns[7], ], 
                                "SessionExpiration": [], "SQLInjection": [vulns[2], vulns[3], vulns[4], ], "SensitiveCookieWithoutSecure": [],
                                "Weak_PRNG": [vulns[9], ], "WeakCrypto": [vulns[5], vulns[6], vulns[13], ], "XPath": [], "XSS": [vulns[10], ]}


    list_juliet = {}
    list_horusec = {}
    attr_atual = ""
    lines = f_horusec.readlines()
    len_lines = len(lines)
    next_line = 0
    
    attrs = [] #Just to know what are the categories detected

    line_atual = ""
    lines_left = 0

    for l in f_juliet.readlines():
        l_splited = l.split(",")
        #print(l_splited[0])
        if lines_left == 0:
            lines_left = int(l_splited[0])
            aux = File_count_juliet_test(l_splited[1], l_splited[2])
            list_horusec[l_splited[1]] = File_count_juliet_test(l_splited[1], l_splited[2])
            aux.incr(l_splited[2])
            list_juliet[l_splited[1]] = aux
        else:
            if len(l_splited) == 5:
                #list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line[l_splited[1]][0] =
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]][l_splited[1]][0] = int(l_splited[3]) 
            else:
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = l_splited[1]
            
            lines_left -= 1

    for i in range(len_lines):
        if next_line == len_lines:
            break

        if next_line == i:
            count = 0
            name = re.sub(r"(_bad|_goodG2B|_base|a|b|c|d|e|)[.]java",".java",lines[next_line+8].split("\\")[-1][:-6]+".java")
            name2 = re.sub(r"(_bad|_goodG2B|_base|a|b|c|d|e|)[.]java","", name)
            name = name[:-5]
            line = -1
            if re.search("Line: [0-9]+", lines[next_line+4]):
                line = int(re.sub(r"Line: ", "", lines[next_line+4])[:-1])
            else:
                break

            next_line += 13
            if re.search(r"CWE.*",name):
                count = 1
            while  next_line != len_lines and lines[next_line] != "==================================================================================\n":
                if re.search("([0-9]/[0-9])",lines[next_line]) and count == 1:
                    attr_atual = lines[next_line].split(":")[-1][1:-1]
                    for k, v in mapping_benchmark_owasp.items():
                        if attr_atual in v:
                            list_horusec[name2].incr(k)
                            if name in list_horusec[name2].versions:
                                if list_horusec[name2].versions[name][k][0] != 0:
                                    list_horusec[name2].versions[name][k].append(int(line))
                                else:
                                    list_horusec[name2].versions[name][k][0] = int(line)
                                #print(1, list_horusec[name2].versions[name][k], attr_atual)
                            else:
                                list_horusec[name2].versions[name] = list_horusec[name2].line
                                list_horusec[name2].versions[name][k][0] = int(line)
                                #print(2, list_horusec[name2].versions[name][k], attr_atual)
                            break
                next_line += 1
               

    empty = File_count_juliet_test("none")
    for k, v in list_juliet.items():
        if k in list_horusec:
            list_juliet[k].compare2(list_horusec[k])
        else:
            list_juliet[k].compare2(empty)

    for v in list_juliet.values():
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_juliet

def snyk(dic):
    f_juliet = open("expect_test_cases_list/expected.txt", "r")
    f_snyk = open("tools_result/res_snyk.txt", "r")

    vulns = ["Use of a Broken or Risky Cryptographic Algorithm", #0
             "Path Traversal", #1
             "Hardcoded Secret", #2
             "LDAP Injection", #3
             "Cross-site Scripting (XSS)", #4
             "Command Injection", #5
             "SQL Injection", #6
             "Cleartext Transmission of Sensitive Information", #7
             "Improper Neutralization of CRLF Sequences in HTTP Headers", #8
             "Sensitive Cookie Without 'HttpOnly' Flag", #9
             "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", #10
             "Server Information Exposure", #11
             "Open Redirect", #12
             "Use of Hardcoded Credentials", #13
             "Use of Password Hash With Insufficient Computational Effort", #14
            ]
    
    #FALTA 7, 9, 11
    mapping_benchmark_owasp = {"BypassAuthorization":[vulns[12], ],  "ErrorHandling": [], "HardCodedPass": [vulns[13], ], "HardConstant": [vulns[2], ], 
                                "Hash": [vulns[14], ], "HttpSplitting": [vulns[8], ], "LDAP": [vulns[3], ], "LogOutputNeutralization": [vulns[11]],
                                "ObsoleteFunctions": [], "OS_CommandInjection": [vulns[5], ], "Path_Transversal": [vulns[1], ], "SameSeed": [], 
                                "SessionExpiration": [], "SQLInjection": [vulns[6], ], "SensitiveCookieWithoutSecure": [vulns[10], ],
                                "Weak_PRNG": [], "WeakCrypto": [vulns[0], ], "XPath": [], "XSS": [vulns[4], ]}

    list_juliet = {}
    list_snyk = {}
    lines_left = 0

    vuln_atual = ""
    lines = f_snyk.readlines()
    next_line = 0
    
    for l in f_juliet.readlines():
        l_splited = l.split(",")
        #print(l_splited[0])
        if lines_left == 0:
            lines_left = int(l_splited[0])
            aux = File_count_juliet_test(l_splited[1], l_splited[2])
            list_snyk[l_splited[1]] = File_count_juliet_test(l_splited[1], l_splited[2])
            aux.incr(l_splited[2])
            list_juliet[l_splited[1]] = aux
        else:
            if len(l_splited) == 5:
                #list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line[l_splited[1]][0] =
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].line
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]][l_splited[1]][0] = int(l_splited[3]) 
            else:
                list_juliet[re.split("(|[a-z]|_bad|_goodG2B|_base).java", l)[0][1:]].versions[l_splited[0][1:-5]] = l_splited[1]
            
            lines_left -= 1

    for i in range(len(lines)):
        if next_line == i:
            if(lines[i] == "\n"):
                #print(1, lines[i], end="")
                next_line += 1
            elif(lines[i][:-1] in vulns):
                #print(2, lines[i], end="")~
                vuln_atual = lines[i][:-1]
                next_line += 1
            else:
                #print(3, lines[i], end="")
                name = lines[i][:-1].split("/")[-1]
                line = int(lines[next_line+3][:-1])
                name2 = re.sub(r"(_bad|_goodG2B|_base|a|b|c|d|e|)[.]java","",name)
                name = name[:-5]
                next_line += 6
                if(re.search("CWE.*", name)):
                    for k, v in mapping_benchmark_owasp.items():
                        if vuln_atual in v: # lines[i][:-1] equivalent attr_atual
                            if name in list_snyk[name2].versions:
                                if list_snyk[name2].versions[name][k][0] != 0:
                                    list_snyk[name2].versions[name][k].append(int(line))
                                else:
                                    list_snyk[name2].versions[name][k][0] = int(line)
                                #print(1, list_snyk[name2].versions[name][k], attr_atual)
                            else:
                                list_snyk[name2].versions[name] = list_snyk[name2].line
                                list_snyk[name2].versions[name][k][0] = int(line)
                                #print(2, list_snyk[name2].versions[name][k], attr_atual)
                            break
                    pass
    
    empty = File_count_juliet_test("none")
    for k, v in list_juliet.items():
        if k in list_snyk:
            list_juliet[k].compare2(list_snyk[k])
        else:
            list_juliet[k].compare2(empty)
    

    for v in list_juliet.values():
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_juliet

def weights(num_tools):
    file_weights = open("weight_combinations_2_results/WEIGHTS.txt", "r")

    wghts = {}
    lines = file_weights.readlines()
    len_file = len(lines)
    line = 0
    
    for i in range(len_file):
        if i!=line:
            pass
        else:
            vuln = lines[i][:-1]
            wghts[vuln] = {}
            for j in range(num_tools):
                l_splited = lines[i+j+1][:-1].split(" ")
                wghts[vuln][l_splited[0]] = []
                for k in range(1,5):
                    wghts[vuln][l_splited[0]].append(float(l_splited[k]))
            
            line += 1 + num_tools + 2

    return wghts

def main():
    KIUWAN_FILE = open("kiuwan/KIUWAN_FILE.txt", "w")
    dic = {"BypassAuthorization": [0,0,0,0], "ErrorHandling": [0,0,0,0], "HardCodedPass": [0,0,0,0], "HardConstant": [0,0,0,0], "Hash": [0,0,0,0], 
            "HttpSplitting": [0,0,0,0], "LDAP": [0,0,0,0], "LogOutputNeutralization": [0,0,0,0], "ObsoleteFunctions": [0,0,0,0], 
            "OS_CommandInjection": [0,0,0,0], "Path_Transversal": [0,0,0,0], "SameSeed": [0,0,0,0], "SensitiveCookieWithoutSecure": [0,0,0,0],
            "SessionExpiration": [0,0,0,0], "SQLInjection": [0,0,0,0], "Weak_PRNG": [0,0,0,0], "WeakCrypto": [0,0,0,0], "XPath": [0,0,0,0], "XSS": [0,0,0,0], }

    dicdic = {"Path_Transversal": "PATH TRANSVERSAL", "XSS": "XSS", "WeakCrypto": "INSECURE ALGORITHM", "LogOutputNeutralization": "OUTPUT NEUTRALIZATION OF LOGS",
           "SSRF": "SSRF", "HardCodedPass": "HARDCODED CREDENTIALS", "SQLInjection":"SQL INJECTION", "Hash":"WEAK HASH", "HttpSplitting":"HTTP SPLITTING",
           "HardConstant":"HARDCODED CONSTANTS", "BypassAuthorization":"BYPASS AUTHORIZATION", "CSRF": "CSRF", "INSECURE DESERIALIZATION": "INSECURE DESERIALIZATION",
           "XXE": "XXE", "SensitiveCookieWithoutSecure":"BAD PROGRAMMING COOKIES", "Weak_PRNG":"WEAK RANDOM", "LDAP":"LDAP INJECTION", 
           "METHOD TAMPERING": "METHOD TAMPERING", "ObsoleteFunctions":"OUTDATED COMPONENTS", "ErrorHandling":"IMPROPER ERROR HANDLING", "SessionExpiration": "INSUFFICIENT SESSION EXPIRATION",
           "OS_CommandInjection":"OS COMMAND INJECTION", "XPath":"XPATH", "BYPASS AUTHENTICATION": "BYPASS AUTHENTICATION", "TRUST BOUNDARY": "TRUST BOUNDARY", "SameSeed": "SAMESEED"}

    latex = {}
    latex_vulns = {"BYPASS AUTHORIZATION": "Bypassing Authorization",
                    "INSUFFICIENT SESSION EXPIRATION": "Insufficient Session Expiration",
                    "PATH TRANSVERSAL": "Path Traversal",
                    "CSRF": "Cross-Site Request Forgery",
                    "INSECURE ALGORITHM": "Use of Old/Insecure algorithms",
                    "WEAK HASH": "Deprecated Hash Functions",
                    "WEAK RANDOM": "Use of Weak PRNG",
                    "SAMESEED": "Seeds Hard Coded in PRNG",
                    "OS COMMAND INJECTION": "OS Command Injection",
                    "SQL INJECTION": "SQL Injection",
                    "LDAP INJECTION": "LDAP Injection",
                    "XSS": "Cross-Site Scripting",
                    "XPATH": "XPath Injection",
                    "HTTP SPLITTING": "HTTP Response Splitting",
                    "IMPROPER ERROR HANDLING": "Improper Error Handling",
                    "TRUST BOUNDARY": "Trust Boundary Violation",
                    "METHOD TAMPERING": "Method Tampering",
                    "XXE": "XML External Entities",
                    "BAD PROGRAMMING COOKIES": "Bad Programming of Cookies",
                    "HARDCODED CONSTANTS": "Insecure Use of Hard Coded Constants",
                    "OUTDATED COMPONENTS": "Vulnerable Third-Party Components",
                    "BYPASS AUTHENTICATION": "Bypassing Authentication",
                    "HARDCODED CREDENTIALS": "Hard Coded Passwords",
                    "INSECURE DESERIALIZATION": "Insecure Deserialization",
                    "OUTPUT NEUTRALIZATION OF LOGS": "Improper Output Neutralization for Logs",
                    "SSRF": "Server-side Request Forgery"
                  }

    latex_categories = {"A1 Broken Access Control": ["BYPASS AUTHORIZATION", "INSUFFICIENT SESSION EXPIRATION", "PATH TRANSVERSAL", "CSRF"],
                        "A2 Cryptographic Failure": ["INSECURE ALGORITHM", "WEAK HASH", "WEAK RANDOM", "SAMESEED"],
                        "A3 Injection": ["OS COMMAND INJECTION", "SQL INJECTION", "LDAP INJECTION", "XSS", "XPATH", "HTTP SPLITTING"],
                        "A4 Insecure Design": ["IMPROPER ERROR HANDLING", "TRUST BOUNDARY", "METHOD TAMPERING"],
                        "A5 Security Misconfiguration": ["XXE", "BAD PROGRAMMING COOKIES", "HARDCODED CONSTANTS"],
                        "A6 Vulnerable and Outdated Components": ["OUTDATED COMPONENTS"],
                        "A7 Identification and Authentication Failures": ["BYPASS AUTHENTICATION", "HARDCODED CREDENTIALS"],
                        "A8 Software and data integrity failures": ["INSECURE DESERIALIZATION"],
                        "A9 Security Logging and Monitoring Failures": ["OUTPUT NEUTRALIZATION OF LOGS"],
                        "A10 Server-side Request Forgery": ["SSRF"],
                        }

    latex_results = {"BYPASS AUTHORIZATION":[0,0,0,0,0,0],
                    "INSUFFICIENT SESSION EXPIRATION": [0,0,0,0,0,0],
                    "PATH TRANSVERSAL": [0,0,0,0,0,0],
                    "CSRF": [0,0,0,0,0,0],
                    "INSECURE ALGORITHM": [0,0,0,0,0,0],
                    "WEAK HASH": [0,0,0,0,0,0],
                    "WEAK RANDOM": [0,0,0,0,0,0],
                    "SAMESEED": [0,0,0,0,0,0],
                    "OS COMMAND INJECTION": [0,0,0,0,0,0],
                    "SQL INJECTION": [0,0,0,0,0,0],
                    "LDAP INJECTION": [0,0,0,0,0,0],
                    "XSS": [0,0,0,0,0,0],
                    "XPATH": [0,0,0,0,0,0],
                    "HTTP SPLITTING": [0,0,0,0,0,0],
                    "IMPROPER ERROR HANDLING": [0,0,0,0,0,0],
                    "TRUST BOUNDARY": [0,0,0,0,0,0],
                    "METHOD TAMPERING": [0,0,0,0,0,0],
                    "XXE": [0,0,0,0,0,0],
                    "BAD PROGRAMMING COOKIES": [0,0,0,0,0,0],
                    "HARDCODED CONSTANTS": [0,0,0,0,0,0],
                    "OUTDATED COMPONENTS": [0,0,0,0,0,0],
                    "BYPASS AUTHENTICATION": [0,0,0,0,0,0],
                    "HARDCODED CREDENTIALS": [0,0,0,0,0,0],
                    "INSECURE DESERIALIZATION": [0,0,0,0,0,0],
                    "OUTPUT NEUTRALIZATION OF LOGS": [0,0,0,0,0,0],
                    "SSRF": [0,0,0,0,0,0]
                  }

    

    LATEX = open("latex/LATEX_JULIET.txt", "w")
    list_tools = ["Snyk", "Fortify", "Semgrep", "Synopsys", "Horusec", "Kiuwan", "Spotbugs"]

    ll = {}
    for t in list_tools:
        ll[t] = copy.deepcopy(latex_results)

    #spotbugs(copy.deepcopy(dic))
    #fortify(copy.deepcopy(dic))
    #semgrep(copy.deepcopy(dic))
    #synopsys(copy.deepcopy(dic))
    #kiuwaaaan(copy.deepcopy(dic))
    #horusec(copy.deepcopy(dic))
    #snyk(copy.deepcopy(dic))

    FINAL_VULNING_JULIET_2 = {}
    FINAL_VULNING_JULIET_3 = {}
    for k in dicdic.keys():
        FINAL_VULNING_JULIET_2[k] = {}
        FINAL_VULNING_JULIET_3[k] = {}

    tools = ["Snyk", "Fortify", "Semgrep", "Synopsys", "Horusec", "Kiuwan", "Spotbugs"]
    comb_2 = list(itertools.combinations(tools, 2))
    comb_3 = list(itertools.combinations(tools, 3))
    
    comb_2 = list(itertools.combinations(tools, 2))
    for sub in comb_2:
        for vuln in dicdic.keys():
            FINAL_VULNING_JULIET_2[vuln][sub] = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    comb_3 = list(itertools.combinations(tools, 3))
    for sub in comb_3:
        for vuln in dicdic.keys():
            FINAL_VULNING_JULIET_3[vuln][sub] = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]


    dics = {"Snyk": snyk(copy.deepcopy(dic)), 
            "Fortify": fortify(copy.deepcopy(dic)), 
            "Semgrep": semgrep(copy.deepcopy(dic)), 
            "Synopsys": synopsys(copy.deepcopy(dic)), 
            "Horusec": horusec(copy.deepcopy(dic)), 
            "Kiuwan": kiuwaaaan(copy.deepcopy(dic)), 
            "Spotbugs": spotbugs(copy.deepcopy(dic)), 
            }

    list_vulns = ["BypassAuthorization", "ErrorHandling", "HardCodedPass", "HardConstant", "Hash", 
                  "HttpSplitting", "LDAP", "LogOutputNeutralization", "ObsoleteFunctions", 
                  "OS_CommandInjection", "Path_Transversal", "SameSeed", "SensitiveCookieWithoutSecure",
                  "SessionExpiration", "SQLInjection", "Weak_PRNG", "WeakCrypto", "XPath", "XSS"]

    wghts = weights(len(tools))
    vulning = {}
    for v in list_vulns:
        vulning[v] = {}
        for t in tools:
            vulning[v][t] = [0,0,0,0,0,0] #tp, fn, fp, tn, fpfp, tnfp


    #To get negatives and fp correctly
    quantity = {"BypassAuthorization": [0,0,0], "ErrorHandling": [0,0,0], "HardCodedPass": [0,0,0], "HardConstant": [0,0,0], "Hash": [0,0,0], 
            "HttpSplitting": [0,0,0], "LDAP": [0,0,0], "LogOutputNeutralization": [0,0,0], "ObsoleteFunctions": [0,0,0], 
            "OS_CommandInjection": [0,0,0], "Path_Transversal": [0,0,0], "SameSeed": [0,0,0], "SensitiveCookieWithoutSecure": [0,0,0],
            "SessionExpiration": [0,0,0], "SQLInjection": [0,0,0], "Weak_PRNG": [0,0,0], "WeakCrypto": [0,0,0], "XPath": [0,0,0], "XSS": [0,0,0], }

    #ORIGINAL QUANTITY POSITIVES AND NEGATIVES
    for l in open("old/expected_old.txt"):
        l_splited = l.split(",")
        quantity[l_splited[1]][0 if l_splited[2] == "TRUE" else 1] += 1

    for t in dics.keys():
        for k, v in dics[t][0].items():
            quantity[k][2] |= v[3]

    print("###########################PER TOOL############################")
    for t in dics.keys():
        tp, fn, fp, fpfp = 0, 0, 0, 0
        print("################################"+t+"################################")
        
        for k, v in dics[t][0].items():
            vulning[k][t][0] += v[0]
            vulning[k][t][1] += v[1]
            tp += v[0]
            fn += v[1]
            fp += v[2]
            fpfp += v[3]

            ll[t][dicdic[k]][0] += v[0]
            ll[t][dicdic[k]][1] += v[1]

            if k == "SensitiveCookieWithoutSecure":
                print("Vulnerability \"" + k + "\":", "TP: " + str(v[0]) + "|", "FN: " + str(v[1]) + "|", "FP: " + str(v[2]-v[3]) + "("+ str(0) +")|", "TN: " + str(quantity[k][1]+quantity[k][2]-(v[2]-v[3])) + "|")
                fp -= v[3]
                fpfp -= v[3]
                
                vulning[k][t][2] += v[2]-v[3]
                vulning[k][t][3] += quantity[k][1]+quantity[k][2]-(v[2]-v[3])
                
                # LATEX
                ll[t][dicdic[k]][2] += v[2]-v[3]
                ll[t][dicdic[k]][3] += quantity[k][1]+quantity[k][2]-(v[2]-v[3])
                ll[t][dicdic[k]][4] = quantity[k][1]
                ll[t][dicdic[k]][5] = quantity[k][2]
            else:
                if quantity[k][1]+quantity[k][2]-v[2] < 0:
                    print("Vulnerability \"" + k + "\":", "TP: " + str(v[0]) + "|", "FN: " + str(v[1]) + "|", "FP: " + str(quantity[k][1]+quantity[k][2]) + "("+ str(v[3]) +")|", "TN: " + str(0) + "|")
                    fp -= v[2]
                    fp += quantity[k][1]+quantity[k][2]
                    fpfp -= v[3]

                    # LATEX
                    ll[t][dicdic[k]][2] += quantity[k][1]+quantity[k][2]
                    ll[t][dicdic[k]][3] += 0
                    ll[t][dicdic[k]][4] = quantity[k][1]
                    ll[t][dicdic[k]][5] = quantity[k][2]

                    vulning[k][t][2] += quantity[k][1]+quantity[k][2]
                    vulning[k][t][3] += 0
                else:
                    print("Vulnerability \"" + k + "\":", "TP: " + str(v[0]) + "|", "FN: " + str(v[1]) + "|", "FP: " + str(v[2]) + "("+ str(v[3]) +")|", "TN: " + str(quantity[k][1]+quantity[k][2]-v[2]) + "|")
                    vulning[k][t][2] += v[2]
                    vulning[k][t][3] += quantity[k][1]+quantity[k][2]-v[2]

                    # LATEX
                    ll[t][dicdic[k]][2] += v[2]
                    ll[t][dicdic[k]][3] += quantity[k][1]+quantity[k][2]-v[2]
                    ll[t][dicdic[k]][4] = quantity[k][1]
                    ll[t][dicdic[k]][5] = quantity[k][2]

            
        print("[" + str(t) + "]:", "TP: " + str(tp) + "|", "FN: " + str(fn) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(11392-fp) + "|\n")

    # LATEX
    t_1st = ["Snyk", "Fortify", "Semgrep", "Spotbugs"]
    t_2nd = ["Synopsys", "Kiuwan", "Horusec"]

    LATEX.write("\\begin{tiny}\n")
    LATEX.write("\\captionsetup{font=footnotesize}\n")
    LATEX.write("\\centering\n")
    LATEX.write("\\setlength{\\tabcolsep}{3pt}\n")
    LATEX.write("\\begin{longtable}{*{1}{|m{1.5in}|} *{3}{wc{0.35cm}|} *{" + str(4*len(t_1st)) + "}{wc{0.35cm}|} }\n")

    LATEX.write("\\hline\n")
    LATEX.write("\\rowcolor{lightgray}\\multicolumn{4}{|c|}{Vulnerability} & \\multicolumn{" + str(4*len(t_1st)) + "}{c|}{Tools} \\\\\n")
    LATEX.write("\\hline\n")
    
    LATEX.write("\\rowcolor{lightgray} {Name} &  \\multicolumn{3}{|c|}{Total}")
    for t in t_1st:
        LATEX.write(" & \\multicolumn{4}{c|}{" + t + "}")

    LATEX.write("\\\\\n\\hline\n")
    
    for c, vulns in latex_categories.items():
        LATEX.write("\\rowcolor{lightlightgray} " + c + " & P & N & NN")
        for t in t_1st:
            LATEX.write(" & TP & FN & FP & TN")
         
        LATEX.write("\\\\\n")
        LATEX.write("\\hline"+ "\n")

        for k in vulns:
            LATEX.write(latex_vulns[k] + " & " +  str(ll["Snyk"][k][0]+ll["Snyk"][k][1]) +  " & " + str(ll["Snyk"][k][4]) +  " & " + str(ll["Snyk"][k][5]))
            for t in t_1st:
                LATEX.write(" & " + str(ll[t][k][0]) + " & " + str(ll[t][k][1]) + " & " + str(ll[t][k][2]) + " & " + str(ll[t][k][3]))

            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")
        LATEX.write("\n")

    LATEX.write("\\caption{SAST tools output in relation to the Juliet Test Suit - Part1}\n")
    LATEX.write("\\label{table:SAST tools output in relation to the Juliet Test Suit - Part1}\n")
    LATEX.write("\\end{longtable}\n")
    LATEX.write("\\end{tiny}\n")
    

    LATEX.write("\n\n\n")

    LATEX.write("\\begin{tiny}\n")
    LATEX.write("\\captionsetup{font=footnotesize}\n")
    LATEX.write("\\centering\n")
    LATEX.write("\\setlength{\\tabcolsep}{3pt}\n")
    LATEX.write("\\begin{longtable}{*{1}{|m{1.5in}|} *{3}{wc{0.35cm}|} *{" + str(4*len(t_2nd)) + "}{wc{0.35cm}|} }\n")

    LATEX.write("\\hline\n")
    LATEX.write("\\rowcolor{lightgray}\\multicolumn{4}{|c|}{Vulnerability} & \\multicolumn{" + str(4*len(t_2nd)) + "}{c|}{Tools} \\\\\n")
    LATEX.write("\\hline\n")
    
    LATEX.write("\\rowcolor{lightgray} {Name} &  \\multicolumn{3}{|c|}{Total}")
    for t in t_2nd:
        LATEX.write(" & \\multicolumn{4}{c|}{" + t + "}")

    LATEX.write("\\\\\n\\hline\n")
    
    for c, vulns in latex_categories.items():
        LATEX.write("\\rowcolor{lightlightgray} " + c + " & P & N & NN")
        LATEX.write(" & TP & FN & FP & TN"*len(t_2nd))
         
        LATEX.write("\\\\\n")
        LATEX.write("\\hline"+ "\n")

        for k in vulns:
            LATEX.write(latex_vulns[k] + " & " +  str(ll["Snyk"][k][0]+ll["Snyk"][k][1]) +  " & " + str(ll["Snyk"][k][4]) +  " & " + str(ll["Snyk"][k][5]))
            for t in t_2nd:
                LATEX.write(" & " + str(ll[t][k][0]) + " & " + str(ll[t][k][1]) + " & " + str(ll[t][k][2]) + " & " + str(ll[t][k][3]))

            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")
        LATEX.write("\n")

    LATEX.write("\\caption{SAST tools output in relation to the Juliet Test Suit - Part2}\n")
    LATEX.write("\\label{table:SAST tools output in relation to the Juliet Test Suit - Part2}\n")
    LATEX.write("\\end{longtable}\n")
    LATEX.write("\\end{tiny}\n")

    LATEX.write("\n\n")
    LATEX.write("\\newpage")

    LATEX.write("\n\n\n")

    print("\n\n\n\n\n\n\n")
    print("###########################COMBINA 2############################")
    for sub in comb_2:
        tp, fn, fp, fpfp = 0, 0, 0, 0
        dic_sub = {"BypassAuthorization": [0,0,0,0], "ErrorHandling": [0,0,0,0], "HardCodedPass": [0,0,0,0], "HardConstant": [0,0,0,0], "Hash": [0,0,0,0], 
            "HttpSplitting": [0,0,0,0], "LDAP": [0,0,0,0], "LogOutputNeutralization": [0,0,0,0], "ObsoleteFunctions": [0,0,0,0], 
            "OS_CommandInjection": [0,0,0,0], "Path_Transversal": [0,0,0,0], "SameSeed": [0,0,0,0], "SensitiveCookieWithoutSecure": [0,0,0,0],
            "SessionExpiration": [0,0,0,0], "SQLInjection": [0,0,0,0], "Weak_PRNG": [0,0,0,0], "WeakCrypto": [0,0,0,0], "XPath": [0,0,0,0], "XSS": [0,0,0,0], }

        for v_sup1, v_sup2 in zip(dics[sub[0]][1].values(), dics[sub[1]][1].values()):
            for vuln, v1, v2 in zip(v_sup1.dic.keys(), v_sup1.dic.values(), v_sup2.dic.values()):
                tp += v1[0] | v2[0]
                fn += v1[1] & v2[1]
                fp += v1[2] | v2[2]
                fpfp += v1[3] | v2[3]
                dic_sub[vuln][0] += v1[0] | v2[0]
                dic_sub[vuln][1] += v1[1] & v2[1]
                dic_sub[vuln][2] += v1[2] | v2[2]
                dic_sub[vuln][3] += v1[3] | v2[3]

        for key_value, value_sub in dic_sub.items():
            if key_value == "SensitiveCookieWithoutSecure":
                print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(value_sub[1]) + "|", "FP: " + str(value_sub[2]-value_sub[3]) + "("+ str(0) +")|", "TN: " + str(quantity[key_value][1]+quantity[key_value][2]-(value_sub[2]-value_sub[3])) + "|")
                fp -= value_sub[3]
                fpfp -= value_sub[3]
            else:
                if quantity[key_value][1]+quantity[key_value][2]-(value_sub[2]) < 0:
                    print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(value_sub[1]) + "|", "FP: " + str(quantity[key_value][1]+quantity[key_value][2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(0) + "|")
                    fp -= value_sub[2]
                    fp += quantity[key_value][1]+quantity[key_value][2]
                    fpfp -= value_sub[3]
                else:
                    print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(value_sub[1]) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(quantity[key_value][1]+quantity[key_value][2]-(value_sub[2])) + "|")
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FN: " + str(fn) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(11392-fp) + "|\n")

    print("\n\n\n\n\n\n\n")
    print("###########################COMBINA 2 - WEIGHTS############################")
    for sub in comb_2:
        tp, fn, fp, fpfp = [0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]
        dic_sub = {"BypassAuthorization": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "ErrorHandling": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "HardCodedPass": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "HardConstant": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "Hash": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], 
            "HttpSplitting": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "LDAP": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "LogOutputNeutralization": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "ObsoleteFunctions": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], 
            "OS_CommandInjection": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "Path_Transversal": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "SameSeed": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "SensitiveCookieWithoutSecure": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]],
            "SessionExpiration": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "SQLInjection": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "Weak_PRNG": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "WeakCrypto": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "XPath": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "XSS": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], }

        for v_sup1, v_sup2 in zip(dics[sub[0]][1].values(), dics[sub[1]][1].values()):
            for vuln, v1, v2 in zip(v_sup1.dic.keys(), v_sup1.dic.values(), v_sup2.dic.values()):
                for w in range(4):
                    w0 = 1; w1 = 1
                    if v1[1] != 0:
                        w0 = -1

                    if v2[1] != 0:
                        w1 = -1

                    if v1[1] !=0 and v2[1] !=0:
                        tp[w] += v2[0]-v1[0] if wghts[vuln][sub[0]][w] < wghts[vuln][sub[1]][w] else v1[0]-v2[0]
                    else:                   
                        if wghts[vuln][sub[0]][w]*w0 + wghts[vuln][sub[1]][w]*w1 >= 0:
                            tp[w] += v1[0] | v2[0]

                    
                    if v1[1] !=0 and v2[1] !=0:
                        dic_sub[vuln][0][w] += v2[0]-v1[0] if wghts[vuln][sub[0]] < wghts[vuln][sub[1]] else v1[0]-v2[0]
                    else:                   
                        dic_sub[vuln][0][w] += v1[0] | v2[0]

                    w0 = 1; w1 = 1
                    if v1[2] == 0:
                        w0 = -1

                    if v2[2] == 0:
                        w1 = -1

                    if wghts[vuln][sub[0]][w]*w0 + wghts[vuln][sub[1]][w]*w1 >= 0:
                        fp[w] += 1
                        fpfp[w] += 1

                    if wghts[vuln][sub[0]][w]*w0 + wghts[vuln][sub[1]][w]*w1 >= 0:
                        dic_sub[vuln][2][w] += 1
                        dic_sub[vuln][3][w] += 1

        for key_value, value_sub in dic_sub.items():
            if key_value == "SensitiveCookieWithoutSecure":
                v_sub1 = [0,0,0,0]
                v_sub2 = [0,0,0,0]
                v_sub3 = [0,0,0,0]
                for m in range(4):
                    v_sub1[m] = quantity[key_value][0]-value_sub[0][m]
                    v_sub2[m] = value_sub[2][m]-value_sub[3][m]
                    v_sub3[m] = quantity[key_value][1]+quantity[key_value][2]-(value_sub[2][m]-value_sub[3][m])
                    
                    FINAL_VULNING_JULIET_2[key_value][sub][0][m] += value_sub[0][m]
                    FINAL_VULNING_JULIET_2[key_value][sub][1][m] += v_sub1[m]
                    FINAL_VULNING_JULIET_2[key_value][sub][2][m] += v_sub2[m]
                    FINAL_VULNING_JULIET_2[key_value][sub][3][m] += v_sub3[m]

                print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(v_sub1) + "|", "FP: " + str(v_sub2) + "("+ str(0) +")|", "TN: " + str(v_sub3) + "|")
                for m in range(4):
                    fp[m] -= value_sub[3][m]
                    fpfp[m] -= value_sub[3][m]
            else:
                if quantity[key_value][1]+quantity[key_value][2]-(value_sub[2][0]) < 0:
                    v_sub1 = [0,0,0,0]
                    for m in range(4):
                        v_sub1[m] = quantity[key_value][0]-value_sub[0][m]

                        FINAL_VULNING_JULIET_2[key_value][sub][0][m] += value_sub[0][m]
                        FINAL_VULNING_JULIET_2[key_value][sub][1][m] += v_sub1[m]
                        FINAL_VULNING_JULIET_2[key_value][sub][2][m] += quantity[key_value][1]+quantity[key_value][2]
                        FINAL_VULNING_JULIET_2[key_value][sub][3][m] += 0

                    print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(v_sub1) + "|", "FP: " + str(quantity[key_value][1]+quantity[key_value][2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(0) + "|")
                    fp -= value_sub[2]
                    fp += quantity[k][1]+quantity[k][2]
                    fpfp -= value_sub[3]
                else:
                    v_sub1 = [0,0,0,0]
                    v_sub3 = [0,0,0,0]
                    for m in range(4):
                        v_sub1[m] = quantity[key_value][0]-value_sub[0][m]
                        v_sub3[m] = quantity[key_value][1]+quantity[key_value][2]-value_sub[2][m]

                        FINAL_VULNING_JULIET_2[key_value][sub][0][m] += value_sub[0][m]
                        FINAL_VULNING_JULIET_2[key_value][sub][1][m] += v_sub1[m]
                        FINAL_VULNING_JULIET_2[key_value][sub][2][m] += value_sub[2][m]
                        FINAL_VULNING_JULIET_2[key_value][sub][3][m] += v_sub3[m]
                    print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(v_sub1) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(v_sub3) + "|")
        V_SUB1 = [0,0,0,0]
        V_SUB3 = [0,0,0,0]
        for m in range(4):
            V_SUB1[m] = 2615-tp[m]
            V_SUB3[m] = 11392-fp[m]
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FN: " + str(V_SUB1) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(V_SUB3) + "|\n")
        
    print("\n\n\n\n\n\n\n")
    print("###########################COMBINA 3############################")
    for sub in comb_3:
        tp, fn, fp, fpfp = 0, 0, 0, 0
        dic_sub = {"BypassAuthorization": [0,0,0,0], "ErrorHandling": [0,0,0,0], "HardCodedPass": [0,0,0,0], "HardConstant": [0,0,0,0], "Hash": [0,0,0,0], 
            "HttpSplitting": [0,0,0,0], "LDAP": [0,0,0,0], "LogOutputNeutralization": [0,0,0,0], "ObsoleteFunctions": [0,0,0,0], 
            "OS_CommandInjection": [0,0,0,0], "Path_Transversal": [0,0,0,0], "SameSeed": [0,0,0,0], "SensitiveCookieWithoutSecure": [0,0,0,0],
            "SessionExpiration": [0,0,0,0], "SQLInjection": [0,0,0,0], "Weak_PRNG": [0,0,0,0], "WeakCrypto": [0,0,0,0], "XPath": [0,0,0,0], "XSS": [0,0,0,0], }

        for v_sup1, v_sup2, v_sup3 in zip(dics[sub[0]][1].values(), dics[sub[1]][1].values(), dics[sub[2]][1].values()):
            for vuln, v1, v2, v3 in zip(v_sup1.dic.keys(), v_sup1.dic.values(), v_sup2.dic.values(), v_sup3.dic.values()):
                tp += v1[0] | v2[0] | v3[0]
                fn += v1[1] & v2[1] & v3[1]
                fp += v1[2] | v2[2] | v3[2]
                fpfp += v1[3] | v2[3] | v3[3]
                dic_sub[vuln][0] += v1[0] | v2[0] | v3[0]
                dic_sub[vuln][1] += v1[1] & v2[1] & v3[1]
                dic_sub[vuln][2] += v1[2] | v2[2] | v3[2]
                dic_sub[vuln][3] += v1[3] | v2[3] | v3[3]

        for key_value, value_sub in dic_sub.items():
            if key_value == "SensitiveCookieWithoutSecure":
                print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(value_sub[1]) + "|", "FP: " + str(value_sub[2]-value_sub[3]) + "("+ str(0) +")|", "TN: " + str(quantity[key_value][1]+quantity[key_value][2]-(value_sub[2]-value_sub[3])) + "|")
                fp -= value_sub[3]
                fpfp -= value_sub[3]
            else:
                if quantity[key_value][1]+quantity[key_value][2]-(value_sub[2]) < 0:
                    print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(value_sub[1]) + "|", "FP: " + str(quantity[key_value][1]+quantity[key_value][2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(0) + "|")
                    fp -= value_sub[2]
                    fp += quantity[key_value][1]+quantity[key_value][2]
                    fpfp -= value_sub[3]
                else:
                    print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(value_sub[1]) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(quantity[key_value][1]+quantity[key_value][2]-(value_sub[2])) + "|")
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FN: " + str(fn) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(11392-fp) + "|\n")

    print("\n\n\n\n\n\n\n")
    '''print("###########################COMBINA 3 - WEIGHTS############################")
    for sub in comb_3:
        tp, fn, fp, fpfp = [0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]
        dic_sub = {"BypassAuthorization": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "ErrorHandling": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "HardCodedPass": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "HardConstant": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "Hash": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], 
            "HttpSplitting": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "LDAP": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "LogOutputNeutralization": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "ObsoleteFunctions": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], 
            "OS_CommandInjection": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "Path_Transversal": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "SameSeed": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "SensitiveCookieWithoutSecure": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]],
            "SessionExpiration": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "SQLInjection": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "Weak_PRNG": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "WeakCrypto": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "XPath": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "XSS": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], }


        for v_sup1, v_sup2, v_sup3 in zip(dics[sub[0]][1].values(), dics[sub[1]][1].values(), dics[sub[2]][1].values()):
            for vuln, v1, v2, v3 in zip(v_sup1.dic.keys(), v_sup1.dic.values(), v_sup2.dic.values(), v_sup3.dic.values()):
                for w in range(4):
                    w0 = 1; w1 = 1; w2 = 1
                    if v1[1] != 0:
                        w0 = -1

                    if v2[1] != 0:
                        w1 = -1
                    
                    if v3[1] != 0:
                        w2 = -1

                    if v1[1] !=0 and v2[1] !=0 and v3[0] !=0:
                        maxi = 0
                        mini = min(min(v2[0],v1[0]),v3[0])

                        lst = [v1, v2, v3]
                        lst2 = [w0, w1, w2]
                        if wghts[vuln][sub[0]][w]*w0 + wghts[vuln][sub[1]][w]*w1 + wghts[vuln][sub[2]][w]*w2 >= 0:
                            for e in range(3):
                                if lst2[e] != -1:
                                    maxi = max(maxi, lst[e][0])

                            for e in range(3):
                                if lst2[e] != -1:
                                    mini = min(mini, lst[e][0])

                            tp[w] += maxi-mini
                        else:
                            for e in range(3):
                                if lst2[e] != 1:
                                    maxi = max(maxi, lst[e][0])

                            for e in range(3):
                                if lst2[e] != 1:
                                    mini = min(mini, lst[e][0])

                            tp[w] += maxi-mini
                    else:                   
                        if wghts[vuln][sub[0]][w]*w0 + wghts[vuln][sub[1]][w]*w1 + wghts[vuln][sub[2]][w]*w2 >= 0:
                            tp[w] += v1[0] | v2[0] | v3[0] 

                    
                    if v1[1] !=0 and v2[1] !=0 and v3[0] !=0:
                        dic_sub[vuln][0][w] += v2[0]-v1[0] if wghts[vuln][sub[0]] < wghts[vuln][sub[1]] else v1[0]-v2[0]
                    else:                   
                        dic_sub[vuln][0][w] += v1[0] | v2[0] | v3[0] 

                    w0 = 1; w1 = 1
                    if v1[2] == 0:
                        w0 = -1

                    if v2[2] == 0:
                        w1 = -1

                    if v3[2] == 0:
                        w2 = -1

                    if wghts[vuln][sub[0]][w]*w0 + wghts[vuln][sub[1]][w]*w1 + wghts[vuln][sub[2]][w]*w2>= 0:
                        fp[w] += 1
                        fpfp[w] += 1

                    if wghts[vuln][sub[0]][w]*w0 + wghts[vuln][sub[1]][w]*w1 + wghts[vuln][sub[2]][w]*w2>= 0:
                        dic_sub[vuln][2][w] += 1
                        dic_sub[vuln][3][w] += 1

        for key_value, value_sub in dic_sub.items():
            
            if key_value == "SensitiveCookieWithoutSecure":
                v_sub1 = [0,0,0,0]
                v_sub2 = [0,0,0,0]
                v_sub3 = [0,0,0,0]
                for m in range(4):
                    v_sub1[m] = quantity[key_value][0]-value_sub[0][m]
                    v_sub2[m] = value_sub[2][m]-value_sub[3][m]
                    v_sub3[m] = quantity[key_value][1]+quantity[key_value][2]-(value_sub[2][m]-value_sub[3][m])

                    FINAL_VULNING_JULIET_3[key_value][sub][0][m] += value_sub[0][m]
                    FINAL_VULNING_JULIET_3[key_value][sub][1][m] += v_sub1[m]
                    FINAL_VULNING_JULIET_3[key_value][sub][2][m] += v_sub2[m]
                    FINAL_VULNING_JULIET_3[key_value][sub][3][m] += v_sub3[m]

                print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(v_sub1) + "|", "FP: " + str(v_sub2) + "("+ str(0) +")|", "TN: " + str(v_sub3) + "|")
                for m in range(4):
                    fp[m] -= value_sub[3][m]
                    fpfp[m] -= value_sub[3][m]
            else:
                if quantity[key_value][1]+quantity[key_value][2]-(value_sub[2][0]) < 0:
                    v_sub1 = [0,0,0,0]
                    for m in range(4):
                        v_sub1[m] = quantity[key_value][0]-value_sub[0][m]

                        FINAL_VULNING_JULIET_3[key_value][sub][0][m] += value_sub[0][m]
                        FINAL_VULNING_JULIET_3[key_value][sub][1][m] += v_sub1[m]
                        FINAL_VULNING_JULIET_3[key_value][sub][2][m] += quantity[key_value][1]+quantity[key_value][2]
                        FINAL_VULNING_JULIET_3[key_value][sub][3][m] += 0

                    print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(v_sub1) + "|", "FP: " + str(quantity[key_value][1]+quantity[key_value][2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(0) + "|")
                    fp -= value_sub[2]
                    fp += quantity[k][1]+quantity[k][2]
                    fpfp -= value_sub[3]
                else:
                    v_sub1 = [0,0,0,0]
                    v_sub3 = [0,0,0,0]
                    for m in range(4):
                        v_sub1[m] = quantity[key_value][0]-value_sub[0][m]
                        v_sub3[m] = quantity[key_value][1]+quantity[key_value][2]-value_sub[2][m]

                        FINAL_VULNING_JULIET_3[key_value][sub][0][m] += value_sub[0][m]
                        FINAL_VULNING_JULIET_3[key_value][sub][1][m] += v_sub1[m]
                        FINAL_VULNING_JULIET_3[key_value][sub][2][m] += value_sub[2][m]
                        FINAL_VULNING_JULIET_3[key_value][sub][3][m] += v_sub3[m]
                    print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(v_sub1) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(v_sub3) + "|")
        V_SUB1 = [0,0,0,0]
        V_SUB3 = [0,0,0,0]
        for m in range(4):
            V_SUB1[m] = 2615-tp[m]
            V_SUB3[m] = 11392-fp[m]
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FN: " + str(V_SUB1) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(V_SUB3) + "|\n")

'''
        
    #Positives, Negatives and FP to Add
    print("\n\n\n\n\n\n\n")
    print("###########################P, N, FP QUANTITY############################")
    p, n, fp = 0, 0, 0
    for k, v in quantity.items():
        p += quantity[k][0]
        n += quantity[k][1]
        fp += quantity[k][2]
        print("Vulnerability \"" + k + "\":", "P: " + str(quantity[k][0]) + "|", "N: " + str(quantity[k][1]) + "|", "FP: " + str(quantity[k][2]) + "|", "N+FP (Total Negatives): " + str(quantity[k][1]+quantity[k][2]) + "|")
    print("[Total]:", "P: " + str(p) + "|", "N: " + str(n) + "|", "FP: " + str(fp) + "|", "N+FP (Total Negatives): " + str(n+fp))
   
    
    for k, v in dics["Kiuwan"][1].items():
        if v.marked == 1 and v.kiuwan_marked>0:
            KIUWAN_FILE.write("TP:" + k + ", " + v.typ + "\n")
        elif v.marked == 1 and v.kiuwan_marked<=0:
            KIUWAN_FILE.write("FN:" + k + ", " + v.typ + "\n")
        elif v.marked == 0 and v.kiuwan_marked>0:
            KIUWAN_FILE.write(" FP:" + k + ", " + v.typ + "\n")
        else:
            KIUWAN_FILE.write("TN:" + k + ", " + v.typ + "\n")

    file_per_vuln = open("VULNING_JULIET.txt", "w+")
    for v in list_vulns:
        file_per_vuln.write(v + ":\n")
        for t in tools: 
            if t == "SpotBugs":
                vulning[v][t][1] = vulning[v]["Snyk"][0]+vulning[v]["Snyk"][1]-vulning[v][t][0]
                vulning[v][t][3] = vulning[v]["Snyk"][2]+vulning[v]["Snyk"][4] + vulning[v]["Snyk"][3]+vulning[v]["Snyk"][5] - vulning[v][t][2]
                vulning[v][t][5] = 0
                
            file_per_vuln.write("\t"+ t + ":" + " TP: " + str(vulning[v][t][0]) 
                                              + " |FN: " + str(vulning[v][t][1]) 
                                              + " |FP: " + str(vulning[v][t][2] + vulning[v][t][4]) 
                                              + " |TN: " + str(vulning[v][t][3] + vulning[v][t][5]) + "|\n")

        file_per_vuln.write("\n\n")  

    FILE = open("weight_combinations_2_results/FINAL_VULNING_2.txt", "a")
    for k, v in FINAL_VULNING_JULIET_2.items():
        FILE.write(dicdic[k] + "\n")
        FILE.write("Tool;Recall;Recall*Informedness;F-measure;Markedness;Precision;TP;TP;TP;TP;FN;FN;FN;FN;FP;FP;FP;FP;TN;TN;TN;TN;\n")
        
        for k2, v2 in v.items():
            line = str(k2) + ";0;0;0;0;0;"
            for i in range(4):
                for j in range(4):
                    line += str(v2[i][j]) + ";"
            FILE.write(line + "\n")

        FILE.write("\n")
        FILE.write("\n")

    '''FILE = open("FINAL_VULNING_3.txt", "a")
    for k, v in FINAL_VULNING_JULIET_3.items():
        FILE.write(dicdic[k] + "\n")
        FILE.write("Tool;Recall;Recall*Informedness;F-measure;Markedness;Precision;TP;TP;TP;TP;FN;FN;FN;FN;FP;FP;FP;FP;TN;TN;TN;TN;\n")
        
        for k2, v2 in v.items():
            line = str(k2) + ";0;0;0;0;0;"
            for i in range(4):
                for j in range(4):
                    line += str(v2[i][j]) + ";"
            FILE.write(line + "\n")

        FILE.write("\n")
        FILE.write("\n")
    '''
            
if __name__=="__main__":
    main()