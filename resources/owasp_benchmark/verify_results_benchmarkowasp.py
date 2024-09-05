
from xml.dom import minidom
import re, copy, itertools

class File_count_benchmark_owasp:
    def __init__(self, name, typ=""):
        self.marked = 0
        self.kiuwan_marked = 0
        self.typ = typ
        self.name = name
        self.cmdi = 0 
        self.crypto = 0
        self.hash = 0
        self.ldapi = 0
        self.pathtraver = 0
        self.securecookie = 0
        self.sqli = 0
        self.trustbound = 0
        self.weakrand = 0
        self.xpathi = 0
        self.xss = 0
        self.dic = {"cmdi": [0,0,0,0], "crypto": [0,0,0,0], "hash": [0,0,0,0], "ldapi": [0,0,0,0], "pathtraver": [0,0,0,0], 
                    "sqli": [0,0,0,0], "trustbound": [0,0,0,0], "weakrand": [0,0,0,0], "xpathi": [0,0,0,0], "xss": [0,0,0,0], "cookies": [0,0,0,0]}
                    #[tp, fn, fp]
        self.sil = 0
        self.cookies = [0,0,0,0] #secure, #httponly, #samesite, #expirationtime

    def incr(self, name, n=1):
        setattr(self, name, getattr(self, name)+n)

    def __str__(self):
        return "How many was detected in " + self.name + ":\n" +\
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
            "xss: " + str(self.xss) + "\n"
    
    def print_sil(self):
        print(self.name + ": " + str(self.sil))

    def compare(self, another, tool=""):
        attrs = ["cmdi", "crypto", "hash", "ldapi", "pathtraver", "sqli", "trustbound", "weakrand", "xpathi", "xss", "cookies"] #"cookies"
        
        for attr in attrs:
            if attr == "cookies":
                self.compare_cookies(another)
            else:
                if getattr(self, attr) == 0 and getattr(another, attr) > 0:
                    self.dic[attr][2] += 1
                    if self.typ != attr:
                        self.dic[attr][3] += 1
                    self.kiuwan_marked += 1
                elif getattr(self, attr) > 0:
                    if getattr(another, attr) >= getattr(self, attr):
                        self.dic[attr][0] += 1
                        self.marked
                        self.kiuwan_marked += 1
                    else:
                        self.dic[attr][1] += 1

    def compare_cookies(self, another):
        for i in range(4):
            if self.cookies[i] == 0 and another.cookies[i] > 0:
                self.dic["cookies"][2] += another.cookies[i]
            elif self.cookies[i] > 0:
                if another.cookies[i] >= self.cookies[i]:
                    self.dic["cookies"][0] += self.cookies[i]
                else:
                    self.dic["cookies"][1] += self.cookies[i] - another.cookies[i]
        
        #print(self.name, self.dic["cookies"])

def spotbugs(dic):
     #Vulnerabilities that are not cookies
    f_benchmark = open("expect_test_cases_list/expectedresults-1.2.csv", "r")
    f_spotbugs = minidom.parse("tools_result/res_spotbugs.xml")
    models = f_spotbugs.getElementsByTagName('BugInstance')
    vulns = ["COMMAND_INJECTION", #0
            "HTTPONLY_COOKIE", #1
            "INSECURE_COOKIE", #2
            "XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER", #3
            "DES_USAGE", #4
            "TDES_USAGE", #5
            "HTTP_RESPONSE_SPLITTING", 
            "HRS_REQUEST_PARAMETER_TO_COOKIE",
            "HARD_CODE_PASSWORD", 
            "INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE",
            "LDAP_INJECTION", #10
            "WEAK_MESSAGE_DIGEST_MD5", #11
            "PT_ABSOLUTE_PATH_TRAVERSAL", #12
            "PT_RELATIVE_PATH_TRAVERSAL", #13
            "PATH_TRAVERSAL_OUT", #14
            "PATH_TRAVERSAL_IN", #15
            "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE", #16
            "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING", #17
            "XSS_SERVLET", #18
            "PREDICTABLE_RANDOM", #19
            "WEAK_MESSAGE_DIGEST_SHA1", #20
            "SQL_INJECTION_JDBC", #21
            "SQL_INJECTION_SPRING_JDBC", #22
            "STATIC_IV", 
            "TRUST_BOUNDARY_VIOLATION", #24
            "URL_REWRITING", 
            "XPATH_INJECTION"] #26

    mapping_benchmark_owasp = {"cmdi":[vulns[0]], 
                                "crypto": [vulns[4], vulns[5]], 
                                "hash": [vulns[11], vulns[20]], 
                                "ldapi": [vulns[10]], 
                                "pathtraver": [vulns[12], vulns[13], vulns[14], vulns[15]], 
                                "securecookie": [vulns[1], vulns[2]], 
                                "sqli": [vulns[16], vulns[17], vulns[21], vulns[22]], 
                                "trustbound": [vulns[24]], 
                                "weakrand": [vulns[19]], 
                                "xpathi": [vulns[26]], 
                                "xss": [vulns[3], vulns[18]]}
    
    list_benchmark = []
    list_spotbugs = []
    index_spotbugs = -1

    for l in f_benchmark.readlines():
        l_splited = l.split(",")
        aux = File_count_benchmark_owasp(l_splited[0], l_splited[1])
        list_spotbugs.append(File_count_benchmark_owasp(l_splited[0]))
        if l_splited[2] == "TRUE":
            aux.incr(l_splited[1])
        
        list_benchmark.append(aux)
    
    
    for l in open("expect_test_cases_list/result_vuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 0
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])
    
    for l in open("expect_test_cases_list/result_nonvuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 1
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])

    actual_value = "BenchmarkTest00000"
    for elem in models:
        if elem.attributes['category'].value == "SECURITY" and elem.attributes['type'].value in vulns and re.search("BenchmarkTest.",elem.childNodes[1].childNodes[1].attributes['sourcefile'].value):
            #print(len(elem.childNodes))
            #print(elem.childNodes[1].attributes['classname'].value + "////" + elem.childNodes[3].attributes['classname'].value)
            name = elem.childNodes[1].childNodes[1].attributes['sourcefile'].value.split(".")[0]
            name_index = int(name[-5:])-1

            for k, v in mapping_benchmark_owasp.items():
                if elem.attributes['type'].value in v:
                    if elem.attributes['type'].value == "HTTPONLY_COOKIE":
                        list_spotbugs[name_index].cookies[1] += 1
                    elif elem.attributes['type'].value == "INSECURE_COOKIE":
                        list_spotbugs[name_index].cookies[0] += 1
                    else:
                        list_spotbugs[name_index].incr(k)
                    break
            
    index_spotbugs = 0
    len_spotbugs = len(list_spotbugs)
    empty = File_count_benchmark_owasp("none")
    for v in list_benchmark:
        order_benchmark = int(v.name[-5:])
        for i in range(index_spotbugs, len_spotbugs):
            order_spotbugs = int(list_spotbugs[i].name[-5:])
            if order_benchmark == order_spotbugs:
                index_spotbugs +=1
                v.compare(list_spotbugs[i])
                break
            elif order_benchmark < order_spotbugs:
                v.compare(empty)
                break

    for v in list_benchmark:
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_benchmark

def fortify(dic):
    f_benchmark = open("expect_test_cases_list/expectedresults-1.2.csv", "r")
    f_fortify = open("tools_result/res_fortify.txt", "r")

    vulns = ["Command Injection", #0
            "Cookie Security: Cookie not Sent Over SSL", #1
            "Cookie Security: Persistent Cookie", #2
            "Cross-Site Request Forgery",
            "Cross-Site Scripting: DOM", #4
            "Cross-Site Scripting: Reflected", #5
            "Insecure Randomness", #6
            "LDAP Injection", #7
            "Missing XML Validation", #8
            "Obsolete",
            "Password Management: Hardcoded Password", 
            "Path Manipulation", #11
            "Poor Error Handling: Empty Catch Block", 
            "Poor Error Handling: Overly Broad Catch",
            "Poor Error Handling: Overly Broad Throws", 
            "Poor Error Handling: Throw Inside Finally", 
            "Poor Logging Practice: Use of a System Output Stream", 
            "SQL Injection", #17
            "System Information Leak", #18
            "System Information Leak: Incomplete Servlet Error Handling", 
            "Trust Boundary Violation", #20
            "Weak Cryptographic Hash", #21
            "Weak Encryption", #22
            "XPath Injection"] #23

    mapping_benchmark_owasp = {"cmdi":[vulns[0]], 
                                "crypto": [vulns[22]], 
                                "hash": [vulns[21]], 
                                "ldapi": [vulns[7]], 
                                "pathtraver": [vulns[11]], 
                                "securecookie": [vulns[1], vulns[2]], 
                                "sqli": [vulns[17]], 
                                "trustbound": [vulns[20]], 
                                "weakrand": [vulns[6]], 
                                "xpathi": [vulns[23]], 
                                "xss": [vulns[4], vulns[5]]}

    list_benchmark = []
    list_fortify = []
    attr_atual = ""

    for l in f_benchmark.readlines():
        l_splited = l.split(",")
        aux = File_count_benchmark_owasp(l_splited[0], l_splited[1])
        list_fortify.append(File_count_benchmark_owasp(l_splited[0]))
        if l_splited[2] == "TRUE":
            aux.incr(l_splited[1])
        
        list_benchmark.append(aux)
    
    for l in open("expect_test_cases_list/result_vuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 0
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])
    
    for l in open("expect_test_cases_list/result_nonvuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 1
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])

    for l in f_fortify.readlines():
        if l[1] == "\"":
            attr_atual = l.split("\"")[1]
        else:
            name = l.split("/")[-1].split(".")[0]
            if attr_atual in vulns and re.search("BenchmarkTest.", name):
                order_benchmark = int(name[-5:])-1
                if attr_atual == "System Information Leak":
                    if re.search("BenchmarkTest.", name):
                        list_fortify[order_benchmark].incr("sil")
                elif attr_atual == "Cookie Security: Cookie not Sent Over SSL":
                    list_fortify[order_benchmark].cookies[0] += 1
                elif attr_atual == "Cookie Security: Persistent Cookie":
                    list_fortify[order_benchmark].cookies[3] += 1
                else:
                    for k, v in mapping_benchmark_owasp.items():
                        if attr_atual in v:
                            list_fortify[order_benchmark].incr(k)
                            break

    index_fortify = 0
    len_fortify = len(list_fortify)
    empty = File_count_benchmark_owasp("none")
    for v in list_benchmark:
        order_benchmark = int(v.name[-5:])
        for i in range(index_fortify, len_fortify):
            order_fortify = int(list_fortify[i].name[-5:])
            if order_benchmark == order_fortify:
                index_fortify +=1
                v.compare(list_fortify[i])
                break
            elif order_benchmark < order_fortify:
                v.compare(empty)
                break

    for v in list_benchmark:
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_benchmark

def semgrep(dic):
    f_benchmark = open("expect_test_cases_list/expectedresults-1.2.csv", "r")
    f_semgrep = open("tools_result/res_semgrep.txt", "r")

    vulns = ["jdbc-sqli",
             "path-transversal",
             "cmd",
             "weak-random",
             "trust-boundary",
             "ldapi",
             "hash",
             "des",
             "xss",
             "xpath",
             "cookie-secure-flag-false",
             "cookie-missing-samesite",
             "cookie-missing-httponly"
            ]
    mapping_benchmark_owasp = {"cmdi":[vulns[2]], 
                                "crypto": [vulns[7]], 
                                "hash": [vulns[6]], 
                                "ldapi": [vulns[5]], 
                                "pathtraver": [vulns[1]], 
                                "securecookie": [], 
                                "sqli": [vulns[0]], 
                                "trustbound": [vulns[4]], 
                                "weakrand": [vulns[3]], 
                                "xpathi": [vulns[9]], 
                                "xss": [vulns[8]]}

    list_benchmark = []
    list_semgrep = []
    list_benchmark_printstacktrace = []
    lines = f_semgrep.readlines()
    next_line = 0
    attr_atual = ""

    for l in f_benchmark.readlines():
        l_splited = l.split(",")
        aux = File_count_benchmark_owasp(l_splited[0], l_splited[1])
        list_semgrep.append(File_count_benchmark_owasp(l_splited[0]))
        list_benchmark_printstacktrace.append(File_count_benchmark_owasp(l_splited[0]))
        if l_splited[2] == "TRUE":
            aux.incr(l_splited[1])
        
        list_benchmark.append(aux)

    
    for l in open("expect_test_cases_list/result_vuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 0
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])
    
    for l in open("expect_test_cases_list/result_nonvuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 1
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])


    for i in range(len(lines)):
        if next_line == i:
            if(lines[i].split("\n")[0] != "1d"):
                next_line += 1
                attr_atual = lines[i].split("\n")[0]
                #print(attr_atual)
            else: 
                next_line += 6
                name = lines[i+1].split("/")[-1].split(".")[0]
                if re.search("BenchmarkTest.", name):
                    order_benchmark = int(name[-5:])
                    if attr_atual == "sil":
                        list_semgrep[order_benchmark-1].incr("sil")
                    elif attr_atual == "cookie-secure-flag-false":
                        list_semgrep[order_benchmark-1].cookies[0] += 1
                    elif attr_atual == "cookie-missing-samesite":
                        list_semgrep[order_benchmark-1].cookies[2] += 1
                    elif attr_atual == "cookie-missing-httponly":
                        list_semgrep[order_benchmark-1].cookies[1] += 1
                    else:
                        for k, v in mapping_benchmark_owasp.items():
                            if attr_atual in v:
                                list_semgrep[order_benchmark-1].incr(k)
                                break

    index_semgrep = 0
    len_semgrep = len(list_semgrep)
    empty = File_count_benchmark_owasp("none")
    for v in list_benchmark:
        order_benchmark = int(v.name[-5:])
        for i in range(index_semgrep, len_semgrep):
            order_semgrep = int(list_semgrep[i].name[-5:])
            if order_benchmark == order_semgrep:
                index_semgrep +=1
                v.compare(list_semgrep[i])
                break
            elif order_benchmark < order_semgrep:
                v.compare(empty)
                break

    for v in list_benchmark:
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_benchmark

def synopsys(dic):
    f_benchmark = open("expect_test_cases_list/expectedresults-1.2.csv", "r")
    f_synopsys = open("tools_result/res_synopsys.csv", "r")

    vulns = ["Insecure block cipher mode", #0
            "Cipher block chaining with insecure padding", #1
            "SQL injection", #2
            "Cross-site request forgery", #3 NAO FEITO
            "Insecure random value used in security context", #4
            "OS Command Injection", #5
            "Filesystem path", #6
            "Trust boundary violation", #7
            "Tainted environment variable for subprocess", #8
            "LDAP injection", #9
            "XML Path (XPath) Language injection", #10
            "REC: RuntimeException capture", #11 NAO FEITO
            "Cross-site scripting", #12
            "Risky cryptographic hashing function", #13
            "Risky cryptographic function"
            "HttpOnly attribute not set for cookie",
            "Missing or insecure samesite attribute for cookie"] #14

    mapping_benchmark_owasp = {"cmdi":[vulns[5], vulns[8], ], 
                                "crypto": [vulns[0], vulns[1], ], 
                                "hash": [vulns[13], ], 
                                "ldapi": [vulns[9], ], 
                                "pathtraver": [vulns[6], ], 
                                "securecookie": [], 
                                "sqli": [vulns[2], ], 
                                "trustbound": [vulns[7], ], 
                                "weakrand": [vulns[4], ], 
                                "xpathi": [vulns[10], ], 
                                "xss": [vulns[12], ]}

    list_benchmark = []
    list_synopsys = []
    attr_atual = ""

    for l in f_benchmark.readlines():
        l_splited = l.split(",")
        aux = File_count_benchmark_owasp(l_splited[0], l_splited[1])
        list_synopsys.append(File_count_benchmark_owasp(l_splited[0]))
        if l_splited[2] == "TRUE":
            aux.incr(l_splited[1])
        
        list_benchmark.append(aux)

    
    for l in open("expect_test_cases_list/result_vuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 0
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])
    
    for l in open("expect_test_cases_list/result_nonvuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 1
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])

    for l in f_synopsys.readlines():
        l = l.split(",")
        attr_atual = l[1]
        #print(attr_atual)
        #print(l)
        name = l[12].split("/")[-1].split(".")[0]
        #print(name)
        if re.search("BenchmarkTest.",name) and attr_atual in vulns:
            if attr_atual == "REC: RuntimeException capture":
                list_synopsys[int(name[-5:])-1].incr("sil")
            elif attr_atual == "HttpOnly attribute not set for cookie":
                list_synopsys[int(name[-5:])-1].cookies[1] += 1
            elif attr_atual == "Missing or insecure samesite attribute for cookie":
                list_synopsys[int(name[-5:])-1].cookies[2] += 1
            else:
                order_benchmark = int(name[-5:])
                for k, v in mapping_benchmark_owasp.items():
                    if attr_atual in v:
                            list_synopsys[order_benchmark-1].incr(k)
                            break


    index_synopsys = 0
    len_synopsys = len(list_synopsys)
    empty = File_count_benchmark_owasp("none")
    for v in list_benchmark:
        order_benchmark = int(v.name[-5:])
        for i in range(index_synopsys, len_synopsys):
            order_synopsys = int(list_synopsys[i].name[-5:])
            if order_benchmark == order_synopsys:
                index_synopsys +=1
                v.compare(list_synopsys[i])
                break
            elif order_benchmark < order_synopsys:
                v.compare(empty)
                break

    for v in list_benchmark:
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_benchmark

def kiuwaaaan(dic):
    f_benchmark = open("expect_test_cases_list/expectedresults-1.2.csv", "r")
    f_kiuwaaaan = open("tools_result/res_kiuwaaaan.csv", "r")

    vulns = ["Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')", #0
            "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", #1
            "Trust boundary violation", #2
            "Cross-site request forgery (CSRF)", #3
            "Improper Neutralization of Data within XPath Expressions ('XPath Injection')", #4
            "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", #5
            "Avoid sensitive information exposure through error messages", #6
            "Avoid calling java.lang.Process from any servlet", #7
            "Always normalize system inputs", #8
            "Weak symmetric encryption algorithm", #9
            "Inadequate padding", #10
            "Do not use the printStackTrace method", #11
            "Weak cryptographic hash", #12
            "Avoid non-neutralized user-controlled input in LDAP search filters", #13
            "Server-Side Request Forgery (SSRF)", #14
            "Avoid non-neutralized user-controlled input composed in a pathname to a resource", #15
            "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", #16
            "Use PreparedStatement instead of Statement to similar requests"]  #17
    
    mapping_benchmark_owasp = {"cmdi":[vulns[5], vulns[7]], 
                                "crypto": [vulns[9], vulns[10]], 
                                "hash": [vulns[12]], 
                                "ldapi": [vulns[13]], 
                                "pathtraver": [vulns[8], vulns[15]], 
                                "securecookie": [], 
                                "sqli": [vulns[16], vulns[17]], 
                                "trustbound": [vulns[2]], 
                                "weakrand": [], 
                                "xpathi": [vulns[4]], 
                                "xss": [vulns[1]]}


    list_benchmark = []
    list_kiuwaaaan = []
    attr_atual = ""

    for l in f_benchmark.readlines():
        l_splited = l.split(",")
        aux = File_count_benchmark_owasp(l_splited[0], l_splited[1])
        list_kiuwaaaan.append(File_count_benchmark_owasp(l_splited[0]))
        if l_splited[2] == "TRUE":
            aux.incr(l_splited[1])
        
        list_benchmark.append(aux)
    
    
    for l in open("expect_test_cases_list/result_vuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 0
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])
    
    for l in open("expect_test_cases_list/result_nonvuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 1
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])


    for l in f_kiuwaaaan.readlines():
        l = l.split(",")
        attr_atual = l[1]
        #print(attr_atual)
        #print(l)
        name = re.sub(r"(_bad|_goodG2B|_base|a|b|c|d|e|)[.]java","",l[6].split("/")[-1].split(".")[0]+".java")
        if re.search("BenchmarkTest.",name) and attr_atual in vulns:
            if attr_atual == "REC: RuntimeException capture":
                list_kiuwaaaan[int(name[-5:])-1].incr("sil")
            else:
                order_benchmark = int(name[-5:])
                for k, v in mapping_benchmark_owasp.items():
                    if attr_atual in v:
                            list_kiuwaaaan[order_benchmark-1].incr(k)
                            break

    index_kiuwaaaan = 0
    len_kiuwaaaan = len(list_kiuwaaaan)
    empty = File_count_benchmark_owasp("none")
    for v in list_benchmark:
        order_benchmark = int(v.name[-5:])
        for i in range(index_kiuwaaaan, len_kiuwaaaan):
            order_synopsys = int(list_kiuwaaaan[i].name[-5:])
            if order_benchmark == order_synopsys:
                index_kiuwaaaan +=1
                v.compare(list_kiuwaaaan[i], "kiuwan")
                break
            elif order_benchmark < order_synopsys:
                v.compare(empty, "kiuwan")
                break

    for v in list_benchmark:
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    return dic, list_benchmark

def horusec(dic):
    f_benchmark = open("expect_test_cases_list/expectedresults-1.2.csv", "r")
    f_horusec = open("tools_result/res_horusec.txt", "r")

    vulns = ["Crypto import", #0
             "Weak block mode for Cryptographic Hash Function", #1
             "DES, DESede, RSA is insecure", #2
             "SQL Injection", #3
             "Weak Cryptographic Hash Function used", #4
             "LDAP deserialization should be disabled", #5
             "Cookie without the HttpOnly flag ", #6
             "Insecure Random Number Generator", #7
             "XPath expressions should not be vulnerable to injection attacks", #8
             "Potential XSS in Servlet",]  #9
    
    mapping_benchmark_owasp = {"cmdi":[], 
                                "crypto": [vulns[0], vulns[1], vulns[2]], 
                                "hash": [vulns[4],], 
                                "ldapi": [vulns[5],], 
                                "pathtraver": [], 
                                "securecookie": [vulns[6],], 
                                "sqli": [vulns[3],], 
                                "trustbound": [], 
                                "weakrand": [vulns[7],], 
                                "xpathi": [vulns[8],], 
                                "xss": [vulns[9],]}


    list_benchmark = []
    list_horusec = []
    attr_atual = ""
    lines = f_horusec.readlines()
    len_lines = len(lines)
    next_line = 0
    
    attrs = [] #Just to know what are the categories detected

    for l in f_benchmark.readlines():
        l_splited = l.split(",")
        aux = File_count_benchmark_owasp(l_splited[0], l_splited[1])
        list_horusec.append(File_count_benchmark_owasp(l_splited[0]))
        if l_splited[2] == "TRUE":
            aux.incr(l_splited[1])
        
        list_benchmark.append(aux)
    
    
    for l in open("expect_test_cases_list/result_vuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 0
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])
    
    for l in open("expect_test_cases_list/result_nonvuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 1
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])

    
    for i in range(len_lines):
        if next_line == len_lines:
            break

        if next_line == i:
            count = 0
            name = lines[next_line+8].split("\\")[-1][:-6]
            #print(name)
            next_line += 13
            if re.search("BenchmarkTest", name):
                #print(name)
                order_benchmark = int(name[-5:])
                count = 1
            while  next_line != len_lines and lines[next_line] != "==================================================================================\n":
                if re.search("([0-9]/[0-9])",lines[next_line]) and count == 1:
                    attr_atual = lines[next_line].split(":")[-1][1:-1]
                    
                    for k, v in mapping_benchmark_owasp.items():
                        if attr_atual in v:
                            if attr_atual == "Cookie without the HttpOnly flag ":
                                list_horusec[order_benchmark-1].cookies[1] += 1
                            else:
                                list_horusec[order_benchmark-1].incr(k)
                            break
                next_line += 1
                #print(next_line)

    index_horusec = 0
    len_horusec = len(list_horusec)
    empty = File_count_benchmark_owasp("none")
    for v in list_benchmark:
        order_benchmark = int(v.name[-5:])
        for i in range(index_horusec, len_horusec):
            order_synopsys = int(list_horusec[i].name[-5:])
            if order_benchmark == order_synopsys:
                index_horusec +=1
                v.compare(list_horusec[i])
                break
            elif order_benchmark < order_synopsys:
                v.compare(empty)
                break

    for v in list_benchmark:
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    #for v in list_synopsys:
    #    if v.sil !=0:
    #        v.print_sil()

    return dic, list_benchmark

def snyk(dic):
    f_benchmark = open("expect_test_cases_list/expectedresults-1.2.csv", "r")
    f_snyk = open("tools_result/res_snyk.txt", "r")

    vulns = ["SQL Injection", #0 
             "Cross-site Scripting (XSS)", #1
             "Use of a Broken or Risky Cryptographic Algorithm", #2
             "Use of Insufficiently Random Values", #3
             "Path Traversal", #4
             "Sensitive Cookie Without 'HttpOnly' Flag", #5
             "Use of Password Hash With Insufficient Computational Effort", #6
             "Command Injection", #7
             "Trust Boundary Violation", #8
             "Indirect Command Injection via User Controlled Environment", #9
             "LDAP Injection", #10
             "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", #11
             "XPath Injection", #12
            ]
    
    mapping_benchmark_owasp = {"cmdi":[vulns[7],vulns[9]], 
                                "crypto": [vulns[2]], 
                                "hash": [vulns[6]], 
                                "ldapi": [vulns[10]], 
                                "pathtraver": [vulns[4]], 
                                "securecookie": [], 
                                "sqli": [vulns[0]], 
                                "trustbound": [vulns[8]], 
                                "weakrand": [vulns[3]], 
                                "xpathi": [vulns[12]], 
                                "xss": [vulns[1]],
                                "cookies": []}


    list_benchmark = []
    list_snyk = []
    attr_atual = ""
    
    vuln_atual = ""
    lines = f_snyk.readlines()
    next_line = 0

    for l in f_benchmark.readlines():
        l_splited = l.split(",")
        aux = File_count_benchmark_owasp(l_splited[0], l_splited[1])
        list_snyk.append(File_count_benchmark_owasp(l_splited[0]))
        if l_splited[2] == "TRUE":
            aux.incr(l_splited[1])
        
        list_benchmark.append(aux)
    
    
    for l in open("expect_test_cases_list/result_vuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 0
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])
    
    for l in open("expect_test_cases_list/result_nonvuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        list_benchmark[name].cookies[0] = int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        list_benchmark[name].cookies[1] = 1
        list_benchmark[name].cookies[2] = int(l_splited[1][0])
        list_benchmark[name].cookies[3] = int(l_splited[1][0]) - int(l_splited[2][0])
    
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
                next_line += 6
                #print(3, lines[i], end="")
                name = lines[i][:-1].split("/")[-1][:-5]
                if re.search("BenchmarkTest.", name):
                    order_benchmark = int(name[-5:])
                    if vuln_atual == "sil":
                        list_snyk[order_benchmark-1].incr("sil")
                    elif vuln_atual == "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute":
                        list_snyk[order_benchmark-1].cookies[0] += 1
                    elif vuln_atual == "Sensitive Cookie Without 'HttpOnly' Flag":
                        list_snyk[order_benchmark-1].cookies[1] += 1
                    else:
                        for k, v in mapping_benchmark_owasp.items():
                            if vuln_atual in v:
                                list_snyk[order_benchmark-1].incr(k)
                                break


    index_snyk = 0
    len_snyk = len(list_snyk)
    empty = File_count_benchmark_owasp("none")
    for v in list_benchmark:
        order_benchmark = int(v.name[-5:])
        for i in range(index_snyk, len_snyk):
            order_snyk = int(list_snyk[i].name[-5:])
            if order_benchmark == order_snyk:
                index_snyk +=1
                v.compare(list_snyk[i])
                break
            elif order_benchmark < order_snyk:
                v.compare(empty)
                break

    for v in list_benchmark:
        for k, v in v.dic.items():
            dic[k][0] += v[0]
            dic[k][1] += v[1]
            dic[k][2] += v[2]
            dic[k][3] += v[3]

    #for v in list_synopsys:
    #    if v.sil !=0:
    #        v.print_sil()

    return dic, list_benchmark

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
    dic = {"cmdi": [0,0,0,0], "crypto": [0,0,0,0], "hash": [0,0,0,0], "ldapi": [0,0,0,0], "pathtraver": [0,0,0,0], 
            "sqli": [0,0,0,0], "trustbound": [0,0,0,0], "weakrand": [0,0,0,0], "xpathi": [0,0,0,0], "xss": [0,0,0,0], "cookies": [0,0,0,0]}
    
    dicdic = {"pathtraver": "PATH TRANSVERSAL", "xss": "XSS", "crypto": "INSECURE ALGORITHM", "OUTPUT NEUTRALIZATION OF LOGS": "OUTPUT NEUTRALIZATION OF LOGS",
           "SSRF": "SSRF", "HARDCODED CREDENTIALS": "HARDCODED CREDENTIALS", "sqli":"SQL INJECTION", "hash":"WEAK HASH", "HTTP SPLITTING":"HTTP SPLITTING",
           "HARDCODED CONSTANTS":"HARDCODED CONSTANTS", "BYPASS AUTHORIZATION":"BYPASS AUTHORIZATION", "CSRF": "CSRF", "INSECURE DESERIALIZATION": "INSECURE DESERIALIZATION",
           "XXE": "XXE", "cookies":"BAD PROGRAMMING COOKIES", "weakrand":"WEAK RANDOM", "ldapi":"LDAP INJECTION", 
           "METHOD TAMPERING": "METHOD TAMPERING", "OUTDATED COMPONENTS":"OUTDATED COMPONENTS", "IMPROPER ERROR HANDLING":"IMPROPER ERROR HANDLING", "SESSION EXPIRATION":"SESSION EXPIRATION",
           "cmdi":"OS COMMAND INJECTION", "xpathi":"XPATH", "BYPASS AUTHENTICATION": "BYPASS AUTHENTICATION", "trustbound": "TRUST BOUNDARY", "SAMESEED": "SAMESEED"}


    #spotbugs(copy.deepcopy(dic))
    #fortify(copy.deepcopy(dic))
    #semgrep(copy.deepcopy(dic))
    #synopsys(copy.deepcopy(dic))
    #kiuwaaaan(copy.deepcopy(dic))
    #horusec(copy.deepcopy(dic))
    #snyk(copy.deepcopy(dic))

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
    LATEX = open("latex/LATEX_OWASPBENCHMARK.txt", "w")
    list_tools = ["Snyk", "Fortify", "Semgrep", "Synopsys", "Horusec", "Kiuwan", "Spotbugs"]

    ll = {}
    for t in list_tools:
        ll[t] = copy.deepcopy(latex_results)

    FINAL_VULNING_OWASP_2 = {}
    FINAL_VULNING_OWASP_3 = {}
    for k in dicdic.keys():
        FINAL_VULNING_OWASP_2[k] = {}
        FINAL_VULNING_OWASP_3[k] = {}

    tools = ["Snyk", "Fortify", "Semgrep", "Synopsys", "Horusec", "Kiuwan", "Spotbugs"]
    comb_2 = list(itertools.combinations(tools, 2))
    comb_3 = list(itertools.combinations(tools, 3))

    comb_2 = list(itertools.combinations(tools, 2))
    for sub in comb_2:
        for vuln in dicdic.keys():
            FINAL_VULNING_OWASP_2[vuln][sub] = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    comb_3 = list(itertools.combinations(tools, 3))
    for sub in comb_3:
        for vuln in dicdic.keys():
            FINAL_VULNING_OWASP_3[vuln][sub] = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]

    list_vulns = ["cmdi", "crypto", "hash", "ldapi", "pathtraver", 
                  "sqli", "trustbound", "weakrand", "xpathi", "xss", "cookies"]

    vulning = {}
    for v in list_vulns:
        vulning[v] = {}
        for t in tools:
            vulning[v][t] = [0,0,0,0,0,0] #tp, fn, fp, tn, fpfp, tnfp
    
    wghts = weights(len(tools))


    dics = {"Snyk": snyk(copy.deepcopy(dic)), 
            "Fortify": fortify(copy.deepcopy(dic)), 
            "Semgrep": semgrep(copy.deepcopy(dic)), 
            "Synopsys": synopsys(copy.deepcopy(dic)), 
            "Horusec": horusec(copy.deepcopy(dic)), 
            "Kiuwan": kiuwaaaan(copy.deepcopy(dic)), 
            "Spotbugs": spotbugs(copy.deepcopy(dic)), 
            }

    #To get negatives and fp correctly
    quantity = {"cmdi": [0,0,0], "crypto": [0,0,0], "hash": [0,0,0], "ldapi": [0,0,0], "pathtraver": [0,0,0], 
                "sqli": [0,0,0], "trustbound": [0,0,0], "weakrand": [0,0,0], "xpathi": [0,0,0], "xss": [0,0,0], "cookies": [0,0,0] }
    
    #ORIGINAL QUANTITY POSITIVES AND NEGATIVES
    for l in open("expect_test_cases_list/expectedresults-1.2.csv"):
        l_splited = l.split(",")
        if l_splited[1] != "securecookie":
            quantity[l_splited[1]][0 if l_splited[2] == "TRUE" else 1] += 1

    for l in open("expect_test_cases_list/result_vuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        #positives
        quantity["cookies"][0] += int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        quantity["cookies"][0] += 0
        quantity["cookies"][0] += int(l_splited[1][0])
        quantity["cookies"][0] += int(l_splited[1][0]) - int(l_splited[2][0])
        #negatives
        quantity["cookies"][1] += (int(l_splited[3][0]) - int(l_splited[4][0]))
        quantity["cookies"][1] += 1
        quantity["cookies"][1] += 0
        quantity["cookies"][1] += int(l_splited[2][0])
    
    for l in open("expect_test_cases_list/result_nonvuln_cookie.txt", "r").readlines():
        l_splited = l.split(" ")
        name = int(l_splited[0][-11:-6])
        #secure, #httponly, #samesite, #expirationtime
        #positives
        quantity["cookies"][0] += int(l_splited[1][0]) - (int(l_splited[3][0]) - int(l_splited[4][0]))
        quantity["cookies"][0] += 1
        quantity["cookies"][0] += int(l_splited[1][0])
        quantity["cookies"][0] += int(l_splited[1][0]) - int(l_splited[2][0])
        #negatives
        quantity["cookies"][1] += (int(l_splited[3][0]) - int(l_splited[4][0]))
        quantity["cookies"][1] += 0
        quantity["cookies"][1] += 0
        quantity["cookies"][1] += int(l_splited[2][0])

    for t in dics.keys():
        for k, v in dics[t][0].items():
            quantity[k][2] |= v[3]

    
    print("###########################PER TOOL############################")
    for t in dics.keys():
        tp, fn, fp, fpfp = 0, 0, 0, 0
        print("################################"+t+"################################")
        for k, v in dics[t][0].items():
            tp += v[0]
            fn += v[1]
            fp += v[2]
            fpfp += v[3]
            vulning[k][t][0] += v[0]
            vulning[k][t][1] += v[1]
            vulning[k][t][2] += v[2]
            vulning[k][t][3] += quantity[k][1]+quantity[k][2]-v[2]

            ll[t][dicdic[k]][0] += v[0]
            ll[t][dicdic[k]][1] += v[1]
            ll[t][dicdic[k]][2] += v[2]
            ll[t][dicdic[k]][3] += quantity[k][1]+quantity[k][2]-v[2]
            ll[t][dicdic[k]][4] = quantity[k][1]
            ll[t][dicdic[k]][5] = quantity[k][2]

            print("Vulnerability \"" + k + "\":", "TP: " + str(v[0]) + "|", "FN: " + str(v[1]) + "|", "FP: " + str(v[2]) + "("+ str(v[3]) +")|", "TN: " + str(quantity[k][1]+quantity[k][2]-v[2]) + "|")
        print("[" + str(t) + "]:", "TP: " + str(tp) + "|", "FN: " + str(fn) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(5441-fp) + "|")

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

    LATEX.write("\\caption{SAST tools output in relation to the OWASP Benchmark - Part1}\n")
    LATEX.write("\\label{table:SAST tools output in relation to the OWASP Benchmark  web application - Part1}\n")
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
    
    LATEX.write("\\rowcolor{lightgray} {Name} &  \\multicolumn{3}{|c|}{Total}")
    for t in t_2nd:
        LATEX.write(" & \\multicolumn{4}{|c|}{" + t + "}")

    LATEX.write("\\\\\n\\hline\n")
    
    for c, vulns in latex_categories.items():
        LATEX.write("\\rowcolor{lightlightgray} " + c + " & P & N & NN")
        for t in t_2nd:
            LATEX.write(" & TP & FN & FP & TN")
         
        LATEX.write("\\\\\n")
        LATEX.write("\\hline"+ "\n")

        for k in vulns:
            LATEX.write(latex_vulns[k] + " & " +  str(ll["Snyk"][k][0]+ll["Snyk"][k][1]) +  " & " + str(ll["Snyk"][k][4]) +  " & " + str(ll["Snyk"][k][5]))
            for t in t_2nd:
                LATEX.write(" & " + str(ll[t][k][0]) + " & " + str(ll[t][k][1]) + " & " + str(ll[t][k][2]) + " & " + str(ll[t][k][3]))

            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")
        LATEX.write("\n")

    LATEX.write("\\caption{SAST tools output in relation to the OWASP Benchmark - Part2}\n")
    LATEX.write("\\label{table:SAST tools output in relation to the OWASP Benchmark web application - Part2}\n")
    LATEX.write("\\end{longtable}\n")
    LATEX.write("\\end{tiny}\n")

    LATEX.write("\n\n")
    LATEX.write("\\newpage")

    LATEX.write("\n\n\n")



    print("\n\n\n\n\n\n\n")
    print("###########################COMBINA 2############################")
    for sub in comb_2:
        tp, fn, fp, fpfp = 0, 0, 0, 0
        dic_sub = {"cmdi": [0,0,0,0], "crypto": [0,0,0,0], "hash": [0,0,0,0], "ldapi": [0,0,0,0], "pathtraver": [0,0,0,0], 
            "sqli": [0,0,0,0], "trustbound": [0,0,0,0], "weakrand": [0,0,0,0], "xpathi": [0,0,0,0], "xss": [0,0,0,0], "cookies": [0,0,0,0]}

        for v_sup1, v_sup2 in zip(dics[sub[0]][1], dics[sub[1]][1]):
            for vuln, v1, v2 in zip(v_sup1.dic.keys(), v_sup1.dic.values(), v_sup2.dic.values()):
                if v1[1] !=0 and v2[1] !=0:
                    tp += v2[0] if v1[0] < v2[0] else v1[0]
                else:                   
                    tp += v1[0] | v2[0]
                
                if v1[1] !=0 and v2[1] !=0:
                    fn += v1[1] if v1[1] < v2[1] else v2[1]
                else:                   
                    fn += v1[1] & v2[1] 

                fp += v1[2] | v2[2]
                fpfp += v1[3] | v2[3]

                if v1[1] !=0 and v2[1] !=0:
                    dic_sub[vuln][0] += v2[0] if v1[0] < v2[0] else v1[0]
                else:                   
                    dic_sub[vuln][0] += v1[0] | v2[0]
                
                if v1[1] !=0 and v2[1] !=0:
                    dic_sub[vuln][1] += v1[1] if v1[1] < v2[1] else v2[1]
                else:                   
                    dic_sub[vuln][1] += v1[1] & v2[1] 
                    
                dic_sub[vuln][2] += v1[2] | v2[2]
                dic_sub[vuln][3] += v1[3] | v2[3]
                #if vuln == "cookies":
                #    print(v1, v2)

        for key_value, value_sub in dic_sub.items():
            print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(quantity[key_value][0]-value_sub[0]) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(quantity[key_value][1]+quantity[key_value][2]-value_sub[2]) + "|")
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FN: " + str(2915-tp) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(5441-fp) + "|")
        

    print("\n\n\n\n\n\n\n")
    print("###########################COMBINA 2 - WEIGHTS############################")
    for sub in comb_2:
        tp, fn, fp, fpfp = [0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]
        dic_sub = {"cmdi": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "crypto": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "hash": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "ldapi": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "pathtraver": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], 
            "sqli": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "trustbound": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "weakrand": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "xpathi": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "xss": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "cookies": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]}

        for v_sup1, v_sup2 in zip(dics[sub[0]][1], dics[sub[1]][1]):
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
                    
                #if vuln == "cookies":
                #    print(v1, v2)

        for key_value, value_sub in dic_sub.items():
            v_sub1 = [0,0,0,0]
            v_sub3 = [0,0,0,0]
            for m in range(4):
                v_sub1[m] = quantity[key_value][0]-value_sub[0][m]
                v_sub3[m] = quantity[key_value][1]+quantity[key_value][2]-value_sub[2][m]

                FINAL_VULNING_OWASP_2[key_value][sub][0][m] += value_sub[0][m]
                FINAL_VULNING_OWASP_2[key_value][sub][1][m] += v_sub1[m]
                FINAL_VULNING_OWASP_2[key_value][sub][2][m] += value_sub[2][m]
                FINAL_VULNING_OWASP_2[key_value][sub][3][m] += v_sub3[m]
            print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(v_sub1) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(v_sub3) + "|")
        V_SUB1 = [0,0,0,0]
        V_SUB3 = [0,0,0,0]
        for m in range(4):
            V_SUB1[m] = 2915-tp[m]
            V_SUB3[m] = 5441-fp[m]
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FN: " + str(V_SUB1) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(V_SUB3) + "|")

    print("\n\n\n\n\n\n\n")
    print("###########################COMBINA 3############################")
    for sub in comb_3:
        tp, fn, fp, fpfp = 0, 0, 0, 0
        dic_sub = {"cmdi": [0,0,0,0], "crypto": [0,0,0,0], "hash": [0,0,0,0], "ldapi": [0,0,0,0], "pathtraver": [0,0,0,0], 
            "sqli": [0,0,0,0], "trustbound": [0,0,0,0], "weakrand": [0,0,0,0], "xpathi": [0,0,0,0], "xss": [0,0,0,0], "cookies": [0,0,0,0]}

        for v_sup1, v_sup2, v_sup3 in zip(dics[sub[0]][1], dics[sub[1]][1], dics[sub[2]][1]):
            for vuln, v1, v2, v3 in zip(v_sup1.dic.keys(), v_sup1.dic.values(), v_sup2.dic.values(), v_sup3.dic.values()):
                if v1[0] !=0 and v2[0] !=0 and v3[0] !=0:
                    tp += v2[0] if v1[0] < v2[0] and v3[0] < v2[0] else v1[0] if v2[0] < v1[0] and v3[0] < v1[0] else v3[0]
                else:                   
                    tp += v1[0] | v2[0] | v3[0]
                
                if v1[1] !=0 and v2[1] !=0 and v3[1] !=0:
                    fn += v1[1] if v1[1] < v2[1] and v1[1] < v3[1] else v2[1] if v2[1] < v1[1] and v2[1] < v3[1] else v3[0]
                else:                   
                    fn += v1[1] & v2[1] & v3[1]

                fp += v1[2] | v2[2] | v3[2]
                fpfp += v1[3] | v2[3] | v3[3]

                if v1[0] !=0 and v2[0] !=0 and v3[0] !=0:
                    dic_sub[vuln][0] += v2[0] if v1[0] < v2[0] and v3[0] < v2[0] else v1[0] if v2[0] < v1[0] and v3[0] < v1[0] else v3[0]
                else:                   
                    dic_sub[vuln][0] += v1[0] | v2[0] | v3[0]
                
                if v1[1] !=0 and v2[1] !=0 and v3[1] !=0:
                    dic_sub[vuln][1] += v1[1] if v1[1] < v2[1] and v1[1] < v3[1] else v2[1] if v2[1] < v1[1] and v2[1] < v3[1] else v3[0]
                else:                   
                    dic_sub[vuln][1] += v1[1] & v2[1] & v3[1]
                    
                dic_sub[vuln][2] += v1[2] | v2[2] | v3[2]
                dic_sub[vuln][3] += v1[3] | v2[3] | v3[3]

        for key_value, value_sub in dic_sub.items():
            print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(value_sub[1]) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(5441-value_sub[2]) + "|")
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FN: " + str(fn) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(5441-fp) + "|")

    print("\n\n\n\n\n\n\n")
    '''print("###########################COMBINA 3 - WEIGHTS############################")
    for sub in comb_3:
        tp, fn, fp, fpfp = [0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]
        dic_sub = {"cmdi": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "crypto": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "hash": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "ldapi": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "pathtraver": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], 
            "sqli": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "trustbound": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "weakrand": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "xpathi": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "xss": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]], "cookies": [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]}

        for v_sup1, v_sup2, v_sup3 in zip(dics[sub[0]][1], dics[sub[1]][1], dics[sub[2]][1]):
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
            v_sub1 = [0,0,0,0]
            v_sub3 = [0,0,0,0]
            for m in range(4):
                v_sub1[m] = quantity[key_value][0]-value_sub[0][m]
                v_sub3[m] = quantity[key_value][1]+quantity[key_value][2]-value_sub[2][m]

                FINAL_VULNING_OWASP_3[key_value][sub][0][m] += value_sub[0][m]
                FINAL_VULNING_OWASP_3[key_value][sub][1][m] += v_sub1[m]
                FINAL_VULNING_OWASP_3[key_value][sub][2][m] += value_sub[2][m]
                FINAL_VULNING_OWASP_3[key_value][sub][3][m] += v_sub3[m]
            print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FN: " + str(v_sub1) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|", "TN: " + str(v_sub3) + "|")
        V_SUB1 = [0,0,0,0]
        V_SUB3 = [0,0,0,0]
        for m in range(4):
            V_SUB1[m] = 2915-tp[m]
            V_SUB3[m] = 5441-fp[m]
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FN: " + str(V_SUB1) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|", "TN: " + str(V_SUB3) + "|")
    '''    


    '''#AGREEMENT
    print("\n\n\n\n\n\n\n")
    print("###########################AGREEMENT############################")
    for sub in comb_2:
        tp, fn, fp, fpfp = 0, 0, 0, 0
        dic_sub = {"cmdi": [0,0,0,0], "crypto": [0,0,0,0], "hash": [0,0,0,0], "ldapi": [0,0,0,0], "pathtraver": [0,0,0,0], 
            "sqli": [0,0,0,0], "trustbound": [0,0,0,0], "weakrand": [0,0,0,0], "xpathi": [0,0,0,0], "xss": [0,0,0,0], "cookies": [0,0,0,0]}

        for v_sup1, v_sup2 in zip(dics[sub[0]][1], dics[sub[1]][1]):
            for vuln, v1, v2 in zip(v_sup1.dic.keys(), v_sup1.dic.values(), v_sup2.dic.values()):
                tp += v1[0] & v2[0]
                fp += (v1[2] | v2[2]) - (((v1[2] | v2[2]) - v1[2])+((v1[2] | v2[2]) - v2[2]))
                fpfp += (v1[3] | v2[3]) - (((v1[3] | v2[3]) - v1[3])+((v1[3] | v2[3]) - v2[3]))
                dic_sub[vuln][0] += v1[0] & v2[0]
                dic_sub[vuln][2] += (v1[2] | v2[2]) - (((v1[2] | v2[2]) - v1[2])+((v1[2] | v2[2]) - v2[2]))
                dic_sub[vuln][3] += (v1[3] | v2[3]) - (((v1[3] | v2[3]) - v1[3])+((v1[3] | v2[3]) - v2[3]))

        for key_value, value_sub in dic_sub.items():
            print("Vulnerability \"" + key_value + "\":", "TP: " + str(value_sub[0]) + "|", "FP: " + str(value_sub[2]) + "("+ str(value_sub[3]) +")|")
        print("[" + str(sub) + "]:", "TP: " + str(tp) + "|", "FP: " + str(fp) + "("+ str(fpfp) +")|\n")'''
   
    

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

    for i in range(len(dics["Kiuwan"][1])):
        v = dics["Kiuwan"][1][i]
        if v.marked == 1 and v.kiuwan_marked>0:
            KIUWAN_FILE.write("TP:" + str(i+1) + ", " + v.typ + "\n")
        elif v.marked == 1 and v.kiuwan_marked<=0:
            KIUWAN_FILE.write("FN:" + str(i+1) + ", " + v.typ + "\n")
        elif v.marked == 0 and v.kiuwan_marked>0:
            KIUWAN_FILE.write("FP:" + str(i+1) + ", " + v.typ + "\n")
        else:
            KIUWAN_FILE.write("TN:" + str(i+1) + ", " + v.typ + "\n")

    file_per_vuln = open("VULNING_BENCHMARK.txt", "w")

    for v in list_vulns:
        file_per_vuln.write(v + ":\n")
        for t in tools: 
            file_per_vuln.write("\t"+ t + ":" + " TP: " + str(vulning[v][t][0]) 
                                              + " |FN: " + str(vulning[v][t][1]) 
                                              + " |FP: " + str(vulning[v][t][2]) 
                                              + " |TN: " + str(vulning[v][t][3]) + "|\n")
    
    FILE = open("weight_combinations_2_results/FINAL_VULNING_2.txt", "w")
    for k, v in FINAL_VULNING_OWASP_2.items():
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
    for k, v in FINAL_VULNING_OWASP_3.items():
        FILE.write(dicdic[k] + "\n")
        FILE.write("Tool;Recall;Recall*Informedness;F-measure;Markedness;Precision;TP;TP;TP;TP;FN;FN;FN;FN;FP;FP;FP;FP;TN;TN;TN;TN;\n")
        
        for k2, v2 in v.items():
            line = str(k2) + ";0;0;0;0;0;"
            for i in range(4):
                for j in range(4):
                    line += str(v2[i][j]) + ";"
            FILE.write(line + "\n")

        FILE.write("\n")
        FILE.write("\n")'''


if __name__=="__main__":
    main()