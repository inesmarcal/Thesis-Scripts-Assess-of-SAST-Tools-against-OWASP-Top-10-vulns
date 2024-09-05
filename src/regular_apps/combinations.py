import pandas as pd, math, re
import itertools
import copy
from functools import cmp_to_key

def compare(x,y):
    if math.floor(x[1]/0.05) > math.floor(y[1]/0.05):
        return -1
    elif math.floor(x[1]/0.05) < math.floor(y[1]/0.05):
        return 1
    else: 
        if x[2] > y[2]:
            return -1
        elif x[2] < y[2]:
            return 1
        else:
            if x[1] > y[1]:
                return -1
            elif x[1] < y[1]:
                return 1
            else:
                return 0


def analyse_results_weighted(wghts):
    dic = {"PATH TRANSVERSAL": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "XSS": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "INSECURE ALGORITHM": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "OUTPUT NEUTRALIZATION OF LOGS": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]],
           "SSRF": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "HARDCODED CREDENTIALS": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "SQL INJECTION": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "WEAK HASH": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "HTTP SPLITTING": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]],
           "HARDCODED CONSTANTS": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "BYPASS AUTHORIZATION": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "CSRF": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "INSECURE DESERIALIZATION": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]],
           "XXE": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "BAD PROGRAMMING COOKIES": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "WEAK RANDOM": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "LDAP INJECTION": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]],
           "METHOD TAMPERING": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "OUTDATED COMPONENTS": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "IMPROPER ERROR HANDLING": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "SESSION EXPIRATION": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], 
           "OS COMMAND INJECTION": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "XPATH": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "BYPASS AUTHENTICATION": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], "TRUST BOUNDARY": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]], 
           "SAMESEED": [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]]}

    print()
    print("WEIGHTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTE")
    print()

    
    FINAL_VULNING_2 = {}
    FINAL_VULNING_3 = {}
    for k in dic.keys():
        FINAL_VULNING_2[k] = {}
        FINAL_VULNING_3[k] = {}

    list_apps = ["Piwigo", "Shopizer", "PeerTube", "JuiceShop", "Mutillidae", "WebGoat", "Metafresh"]
    list_tools = ["Snyk", "Fortify", "Semgrep", "Synopsis", "Horusec", "Kiuwan", "SpotBugs"]
    comb_2 = list(itertools.combinations(list_tools, 2))
    for sub in comb_2:
        for vuln in dic.keys():
            FINAL_VULNING_2[vuln][sub] = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    comb_3 = list(itertools.combinations(list_tools, 3))
    for sub in comb_3:
        for vuln in dic.keys():
            FINAL_VULNING_3[vuln][sub] = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]

    xl = pd.read_excel('GLOBAL_RESULTS.xlsx', sheet_name=None)
    len_tools = len(list_tools)



    for app in list_apps:
        print("=============================================================== " + app + " ===============================================================\n")
        vuln = True
        results = {}
        orders = []

        for index, row in xl[app].iterrows():
            r = []
            for column, value in row.items():
                r.append(str(value).replace('\n', ' ').replace('\r', ''))
            
            if index == 0:
                orders = r[5:]
                if len(orders) == 6:
                    orders.append("SpotBugs")
                continue

            if r[0] == "NON VULNERABLE":
                vuln = False
            elif r[0] == "nan":
                pass
            else:
                results[index] = ({}, r[4])
                for t in list_tools:
                    results[index][0][t] = -1
                for i in range(5, len(r)):
                    if vuln:
                        if r[i] == "x":                    
                            results[index][0][orders[i-5]] = 0
                        else:
                            results[index][0][orders[i-5]] = 1
                    else:
                        if r[i] == "x":
                            results[index][0][orders[i-5]] = 2
                        else:
                            results[index][0][orders[i-5]] = 3

        #COMBINATION 2 RESULTS
        print("##############################################################")
        print("########################COMBINATIONS 2########################")
        res = {}
        per_vuln = {}

        for sub in comb_2:
            res[sub] = [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]]
            per_vuln[sub] = copy.deepcopy(dic)

        for v in results.values():
            for sub in comb_2:
                w0 = 1; w1 = 1
                if v[0][sub[0]] == 1 or v[0][sub[0]] == 3 or v[0][sub[0]] == -1:
                    w0 = -1
                
                if v[0][sub[1]] == 1 or v[0][sub[1]] == 3 or v[0][sub[1]] == -1:
                    w1 = -1
                
                for i in range(4):
                    if wghts[v[1]][i][sub[0]]*w0 + wghts[v[1]][i][sub[1]]*w1 >= 0:
                        if v[0][sub[0]] == 1 or v[0][sub[0]] == 0:
                            res[sub][0][i] += 1
                            per_vuln[sub][v[1]][0][i] += 1
                        else:
                            res[sub][2][i] += 1
                            per_vuln[sub][v[1]][2][i] += 1
                    else:
                        if v[0][sub[0]] == 1 or v[0][sub[0]] == 0:
                            res[sub][1][i] += 1
                            per_vuln[sub][v[1]][1][i] += 1
                        else:
                            res[sub][3][i] += 1
                            per_vuln[sub][v[1]][3][i] += 1

                #res[sub][v[0][sub[0]] & v[0][sub[1]]] += 1
                #per_vuln[sub][v[1]][v[0][sub[0]] & v[0][sub[1]]] += 1

        for sub in comb_2:
            for vuln, value in per_vuln[sub].items():
                for i in range(4):
                    FINAL_VULNING_2[vuln][sub][0][i] += value[0][i]
                    FINAL_VULNING_2[vuln][sub][1][i] += value[1][i]
                    FINAL_VULNING_2[vuln][sub][2][i] += value[2][i]
                    FINAL_VULNING_2[vuln][sub][3][i] += value[3][i]
                print("Vulnerability \"" + vuln + "\":", "TP: " + str(value[0]) + "|", "FN: " + str(value[1]) + "|", "FP: " + str(value[2]) + "|", "TN: " + str(value[3]) + "|",)
            print("[" + str(sub) + "]:", "TP: " + str(res[sub][0]) + " |", "FN: " + str(res[sub][1]) + " |", "FP: " + str(res[sub][2]) + " |", "TN: " + str(res[sub][3]) + " |\n")

        
    FILE = open("results_weights_2/FINAL_VULNING_2.txt", "w")
    for k, v in FINAL_VULNING_2.items():
        FILE.write(k + "\n")
        FILE.write("Tool;Recall;Recall*Informedness;F-measure;Markedness;Precision;TP;TP;TP;TP;FN;FN;FN;FN;FP;FP;FP;FP;TN;TN;TN;TN;\n")
        
        for k2, v2 in v.items():
            line = str(k2) + ";0;0;0;0;0;"
            for i in range(4):
                for j in range(4):
                    line += str(v2[i][j]) + ";"
            FILE.write(line + "\n")

        FILE.write("\n")
        FILE.write("\n")

def analyse_results_fp_weighted(wghts):
    dic = {"PATH TRANSVERSAL": [[0,0,0,0], [0,0,0,0]], "XSS": [[0,0,0,0], [0,0,0,0]], "INSECURE ALGORITHM": [[0,0,0,0], [0,0,0,0]], "OUTPUT NEUTRALIZATION OF LOGS": [[0,0,0,0], [0,0,0,0]],
           "SSRF": [[0,0,0,0], [0,0,0,0]], "HARDCODED CREDENTIALS": [[0,0,0,0], [0,0,0,0]], "SQL INJECTION": [[0,0,0,0], [0,0,0,0]], "WEAK HASH": [[0,0,0,0], [0,0,0,0]], "HTTP SPLITTING": [[0,0,0,0], [0,0,0,0]],
           "HARDCODED CONSTANTS": [[0,0,0,0], [0,0,0,0]], "BYPASS AUTHORIZATION": [[0,0,0,0], [0,0,0,0]], "CSRF": [[0,0,0,0], [0,0,0,0]], "INSECURE DESERIALIZATION": [[0,0,0,0], [0,0,0,0]],
           "XXE": [[0,0,0,0], [0,0,0,0]], "BAD PROGRAMMING COOKIES": [[0,0,0,0], [0,0,0,0]], "WEAK RANDOM": [[0,0,0,0], [0,0,0,0]], "LDAP INJECTION": [[0,0,0,0], [0,0,0,0]],
           "METHOD TAMPERING": [[0,0,0,0], [0,0,0,0]], "OUTDATED COMPONENTS": [[0,0,0,0], [0,0,0,0]], "IMPROPER ERROR HANDLING": [[0,0,0,0], [0,0,0,0]], "INSECURE ALGORITHM": [[0,0,0,0], [0,0,0,0]], 
           "OS COMMAND INJECTION": [[0,0,0,0], [0,0,0,0]], "XPATH": [[0,0,0,0], [0,0,0,0]], "BYPASS AUTHENTICATION": [[0,0,0,0], [0,0,0,0]], "TRUST BOUNDARY": [[0,0,0,0], [0,0,0,0]], }
    
    print()
    print("FP_WEIGHTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTE")
    print()

    list_apps = ["Piwigo", "Shopizer", "PeerTube", "JuiceShop", "Mutillidae", "WebGoat", "Metafresh"]
    list_tools = ["Snyk", "Fortify", "Semgrep", "Synopsis", "Horusec", "Kiuwan", "SpotBugs"]
    comb_2 = list(itertools.combinations(list_tools, 2))
    comb_3 = list(itertools.combinations(list_tools, 3))

    xl = pd.read_excel('GLOBAL_FP.xlsx', sheet_name=None)
    len_tools = len(list_tools)
    base_result = {}

    for t in list_tools:
        base_result[t] = 0

    for app in list_apps:
        print("\n======================= " + app + " =======================")
        results = {}
        tool = ""
        for index, row in xl[app].iterrows():
            r = []
            for column, value in row.items():
                r.append(str(value).replace('\n', ' ').replace('\r', ''))
            
            if r[0] != "nan":
                if r[0] in list_tools:
                    tool = r[0]
                    #print(r)
                else:
                    tupl = (r[0].split("/")[-1], int(float(r[1])), r[2])
                    if tupl not in results:
                        results[tupl] = copy.copy(base_result)
                        results[tupl][tool] = 1
                #print(r)
                
        
        #COMBINATION 2 RESULTS
        print("##############################################################")
        print("########################COMBINATIONS 2########################")
        res = {}
        per_vuln = {}
        for sub in comb_2:
            res[sub] = [[0,0,0,0], [0,0,0,0]]
            per_vuln[sub] = copy.deepcopy(dic)

        for k, v in results.items():
             for sub in comb_2:
                w0 = 1; w1 = 1
                if v[sub[0]] == 0:
                    w0 = -1
                
                if v[sub[1]] == 0:
                    w1 = -1

                for i in range(4):
                    if wghts[k[2]][i][sub[0]]*w0 + wghts[k[2]][i][sub[1]]*w1 >= 0:
                        res[sub][1][i] += 1
                        per_vuln[sub][k[2]][1][i] += 1
                    else:
                        res[sub][0][i] += 1
                        per_vuln[sub][k[2]][0][i] += 1

        for sub in comb_2:
            for vuln, value in per_vuln[sub].items():
                print("Vulnerability \"" + vuln + "\":", "TN: " + str(value[0]) + "|", "FP: " + str(value[1]) + "|")
            print("[" + str(sub) + "]:", "TN: " + str(res[sub][0]) + " |", "FP: " + str(res[sub][1]) + " |\n")

        #COMBINATION 3 RESULTS
        print("##############################################################")
        print("########################COMBINATIONS 3########################")
        res = {}
        per_vuln = {}
        for sub in comb_3:
            res[sub] = [[0,0,0,0], [0,0,0,0]]
            per_vuln[sub] = copy.deepcopy(dic)

        for k, v in results.items():
             for sub in comb_3:
                w0 = 1; w1 = 1; w2 = 1
                if v[sub[0]] == 0:
                    w0 = -1
                
                if v[sub[1]] == 0:
                    w1 = -1

                if v[sub[2]] == 0:
                    w2 = -1

                for i in range(4):
                    if wghts[k[2]][i][sub[0]]*w0 + wghts[k[2]][i][sub[1]]*w1 + wghts[k[2]][i][sub[2]]*w2 >= 0:
                        res[sub][1][i] += 1
                        per_vuln[sub][k[2]][1][i] += 1
                    else:
                        res[sub][0][i] += 1
                        per_vuln[sub][k[2]][0][i] += 1

        for sub in comb_3:
            for vuln, value in per_vuln[sub].items():
                print("Vulnerability \"" + vuln + "\":", "TN: " + str(value[0]) + "|", "FP: " + str(value[1]) + "|")
            print("[" + str(sub) + "]:", "TN: " + str(res[sub][0]) + " |", "FP: " + str(res[sub][1]) + " |\n")
    

def analyse_results(dic, vulning):
    KIUWAN_FILE = open("kiuwan/KIUWAN_FILE.txt", "w")
    list_apps = ["Piwigo", "Shopizer", "PeerTube", "JuiceShop", "Mutillidae", "WebGoat", "Metafresh"]
    list_tools = ["Snyk", "Fortify", "Semgrep", "Synopsis", "Horusec", "Kiuwan", "SpotBugs"]
    comb_2 = list(itertools.combinations(list_tools, 2))
    comb_3 = list(itertools.combinations(list_tools, 3))

    xl = pd.read_excel('GLOBAL_RESULTS.xlsx', sheet_name=None)
    len_tools = len(list_tools)

    per_vuln = {}
    per_vuln_comb2 = {}
    per_vuln_comb3 = {}

    overall_results = {}
    overall_results_comb2 = {}
    overall_results_comb3 = {}

    for t in list_tools:
        overall_results[t] = [0,0,0,0]

    for sub in comb_2:
        overall_results_comb2[sub] = [0,0,0,0]

    for sub in comb_3:
        overall_results_comb3[sub] = [0,0,0,0]


    seila= {"PATH TRANSVERSAL": [0,0,0,0], "XSS": [0,0,0,0], "INSECURE ALGORITHM": [0,0,0,0], "OUTPUT NEUTRALIZATION OF LOGS": [0,0,0,0],
           "SSRF": [0,0,0,0], "HARDCODED CREDENTIALS": [0,0,0,0], "SQL INJECTION": [0,0,0,0], "WEAK HASH": [0,0,0,0], "HTTP SPLITTING": [0,0,0,0],
           "HARDCODED CONSTANTS": [0,0,0,0], "BYPASS AUTHORIZATION": [0,0,0,0], "CSRF": [0,0,0,0], "INSECURE DESERIALIZATION": [0,0,0,0],
           "XXE": [0,0,0,0], "BAD PROGRAMMING COOKIES": [0,0,0,0], "WEAK RANDOM": [0,0,0,0], "LDAP INJECTION": [0,0,0,0],
           "METHOD TAMPERING": [0,0,0,0], "OUTDATED COMPONENTS": [0,0,0,0], "IMPROPER ERROR HANDLING": [0,0,0,0], "INSECURE ALGORITHM": [0,0,0,0], 
           "OS COMMAND INJECTION": [0,0,0,0], "XPATH": [0,0,0,0], "BYPASS AUTHENTICATION": [0,0,0,0], "TRUST BOUNDARY": [0,0,0,0], }
    
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
                    "SSRF": "Server-Side Request Forgery"
                  }

    latex_categories = {"A1 Broken Access Control": ["BYPASS AUTHORIZATION", "INSUFFICIENT SESSION EXPIRATION", "PATH TRANSVERSAL", "CSRF"],
                        "A2 Cryptographic Failure": ["INSECURE ALGORITHM", "WEAK HASH", "WEAK RANDOM", "SAMESEED"],
                        "A3 Injection": ["OS COMMAND INJECTION", "SQL INJECTION", "LDAP INJECTION", "XSS", "XPATH", "HTTP SPLITTING"],
                        "A4 Insecure Design": ["IMPROPER ERROR HANDLING", "TRUST BOUNDARY", "METHOD TAMPERING"],
                        "A5 Security Misconfiguration": ["XXE", "BAD PROGRAMMING COOKIES", "HARDCODED CONSTANTS"],
                        "A6 Vulnerable and Outdated Components": ["OUTDATED COMPONENTS"],
                        "A7 Identification and Authentication Failures": ["BYPASS AUTHENTICATION", "HARDCODED CREDENTIALS"],
                        "A8 Software and Data Integrity Failures": ["INSECURE DESERIALIZATION"],
                        "A9 Security Logging and Monitoring Failures": ["OUTPUT NEUTRALIZATION OF LOGS"],
                        "A10 Server-Side Request Forgery": ["SSRF"],
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
    

    for app in list_apps:
        latex[app] = {}
        for t in list_tools:
            latex[app][t] = copy.deepcopy(latex_results)

        KIUWAN_FILE.write("=============================================================== " + app + " ===============================================================\n")
        #print(app)
        vuln = True
        results = {}
        orders = []

        for index, row in xl[app].iterrows():
            r = []
            for column, value in row.items():
                r.append(str(value).replace('\n', ' ').replace('\r', ''))
            
            if index == 0:
                orders = r[5:]
                if len(orders) == 6:
                    orders.append("SpotBugs")
                continue

            if r[0] == "NON VULNERABLE":
                vuln = False
            elif r[0] == "nan":
                pass
            else:
                results[index] = ({}, r[4])
                for t in list_tools:
                    results[index][0][t] = -1
                for i in range(5, len(r)):
                    if vuln:
                        if r[i] == "x":                    
                            if orders[i-5] == "Kiuwan":
                                KIUWAN_FILE.write("TP:" + str(r[0:2]+[r[4]]) + "\n")
                            results[index][0][orders[i-5]] = 0
                        else:
                            if orders[i-5] == "Kiuwan":
                                KIUWAN_FILE.write("FN:" + str(r[0:2]+[r[4]]) + "\n")
                            results[index][0][orders[i-5]] = 1
                    else:
                        if r[i] == "x":
                            if orders[i-5] == "Kiuwan":
                                KIUWAN_FILE.write("FP:" + str(r[0:2]+[r[4]]) + "\n")
                            results[index][0][orders[i-5]] = 2
                        else:
                            if orders[i-5] == "Kiuwan":
                                KIUWAN_FILE.write("TN:" + str(r[0:2]+[r[4]]) + "\n")
                            results[index][0][orders[i-5]] = 3
                    
                #print(app, index, results[index])

        #INDIVIDUAL RESULTS
        print("\n======================= " + app + " =======================")
        print("##############################################################")
        print("###########################SINGULAR###########################")
        res = {}
        per_vuln = {}

        for t in list_tools:
            res[t] = [0, 0, 0, 0]
            per_vuln[t] = copy.deepcopy(dic)

        for v in results.values():
            for t in list_tools:
                if v[0][t] != -1:
                    res[t][v[0][t]] += 1
                    per_vuln[t][v[1]][v[0][t]] += 1
        
        KIUWAN_FILE.write("\n")

        for t in list_tools:
            overall_results[t][0] += res[t][0]
            overall_results[t][1] += res[t][1]
            overall_results[t][2] += res[t][2]
            overall_results[t][3] += res[t][3]
            for vuln, value in per_vuln[t].items():
                vulning[vuln][t][0] += value[0]
                vulning[vuln][t][1] += value[1]
                vulning[vuln][t][2] += value[2]
                vulning[vuln][t][3] += value[3]

                latex[app][t][vuln][0] += value[0]
                latex[app][t][vuln][1] += value[1]
                latex[app][t][vuln][2] += value[2]
                latex[app][t][vuln][3] += value[3]

                print("Vulnerability \"" + vuln + "\":", "TP: " + str(value[0]) + "|", "FN: " + str(value[1]) + "|", "FP: " + str(value[2]) + "|", "TN: " + str(value[3]) + "|",)
                if t == "Kiuwan":
                    KIUWAN_FILE.write("Vulnerability \"" + vuln + "\": " + "TP: " + str(value[0]) + "| " + "FN: " + str(value[1]) + "| " + "FP: " + str(value[2]) + "| " + "TN: " + str(value[3]) + "|\n",)
            print("[" + t + "]:", "TP: " + str(res[t][0]) + " |", "FN: " + str(res[t][1]) + " |", "FP: " + str(res[t][2]) + " |", "TN: " + str(res[t][3]) + " |\n")
            if t == "Kiuwan":
                KIUWAN_FILE.write("[" + t + "]: " + "TP: " + str(res[t][0]) + "| " + "FN: " + str(res[t][1]) + "| " + "FP: " + str(res[t][2]) + "| " + "TN: " + str(res[t][3]) + "|\n\n")

        

        #COMBINATION 2 RESULTS
        print("##############################################################")
        print("########################COMBINATIONS 2########################")
        res = {}
        per_vuln = {}
        
        for sub in comb_2:
            res[sub] = [0, 0, 0, 0]
            per_vuln[sub] = copy.deepcopy(dic)

        for v in results.values():
             for sub in comb_2:
                res[sub][v[0][sub[0]] & v[0][sub[1]]] += 1
                per_vuln[sub][v[1]][v[0][sub[0]] & v[0][sub[1]]] += 1

        for sub in comb_2:
            overall_results_comb2[sub][0] += res[sub][0]
            overall_results_comb2[sub][1] += res[sub][1]
            overall_results_comb2[sub][2] += res[sub][2]
            overall_results_comb2[sub][3] += res[sub][3]
            for vuln, value in per_vuln[sub].items():
                print("Vulnerability \"" + vuln + "\":", "TP: " + str(value[0]) + "|", "FN: " + str(value[1]) + "|", "FP: " + str(value[2]) + "|", "TN: " + str(value[3]) + "|",)
            print("[" + str(sub) + "]:", "TP: " + str(res[sub][0]) + " |", "FN: " + str(res[sub][1]) + " |", "FP: " + str(res[sub][2]) + " |", "TN: " + str(res[sub][3]) + " |\n")

        #COMBINATION 3 RESULTS
        print("##############################################################")
        print("########################COMBINATIONS 3########################")
        res = {}
        per_vuln = {}

        for sub in comb_3:
            res[sub] = [0, 0, 0, 0]
            per_vuln[sub] = copy.deepcopy(dic)

        for v in results.values():
             for sub in comb_3:
                res[sub][v[0][sub[0]] & v[0][sub[1]] & v[0][sub[2]]] += 1
                per_vuln[sub][v[1]][v[0][sub[0]] & v[0][sub[1]] & v[0][sub[2]]] += 1

        for sub in comb_3:
            overall_results_comb3[sub][0] += res[sub][0]
            overall_results_comb3[sub][1] += res[sub][1]
            overall_results_comb3[sub][2] += res[sub][2]
            overall_results_comb3[sub][3] += res[sub][3]
            for vuln, value in per_vuln[sub].items():
                print("Vulnerability \"" + vuln + "\":", "TP: " + str(value[0]) + "|", "FN: " + str(value[1]) + "|", "FP: " + str(value[2]) + "|", "TN: " + str(value[3]) + "|",)
            print("[" + str(sub) + "]:", "TP: " + str(res[sub][0]) + " |", "FN: " + str(res[sub][1]) + " |", "FP: " + str(res[sub][2]) + " |", "TN: " + str(res[sub][3]) + " |\n")

    print("\n\n\n\n\n\n\n\n##############################################################")
    print("###########################OVERALL 1############################")
    for t in list_tools:
        print("[" + str(t) + "]:", "TP: " + str(overall_results[t][0]) + " |", "FN: " + str(overall_results[t][1]) + " |", "FP: " + str(overall_results[t][2]) + " |", "TN: " + str(overall_results[t][3]) + " |")

    print("###########################OVERALL 2############################")
    for sub in comb_2:
        print("[" + str(sub) + "]:", "TP: " + str(overall_results_comb2[sub][0]) + " |", "FN: " + str(overall_results_comb2[sub][1]) + " |", "FP: " + str(overall_results_comb2[sub][2]) + " |", "TN: " + str(overall_results_comb2[sub][3]) + " |")

    print("###########################OVERALL 3############################")
    for sub in comb_3:
        print("[" + str(sub) + "]:", "TP: " + str(overall_results_comb3[sub][0]) + " |", "FN: " + str(overall_results_comb3[sub][1]) + " |", "FP: " + str(overall_results_comb3[sub][2]) + " |", "TN: " + str(overall_results_comb3[sub][3]) + " |")
    
    



    return overall_results, overall_results_comb2, overall_results_comb3, vulning, results, list_apps, latex, latex_categories, latex_vulns

def analyse_false_positives(dic, vulning, list_apps, latex, latex_categories, latex_vulns):
    KIUWAN_FILE = open("kiuwan/KIUWAN_FILE_FP.txt", "w")
    list_apps = ["Piwigo", "Shopizer", "PeerTube", "JuiceShop", "Mutillidae", "WebGoat", "Metafresh"]
    list_tools = ["Snyk", "Fortify", "Semgrep", "Synopsis", "Horusec", "Kiuwan", "SpotBugs"]
    comb_2 = list(itertools.combinations(list_tools, 2))
    comb_3 = list(itertools.combinations(list_tools, 3))

    xl = pd.read_excel('GLOBAL_FP.xlsx', sheet_name=None)
    len_tools = len(list_tools)
    base_result = {}
    overall_results = {}
    overall_results_comb2 = {}
    overall_results_comb3 = {}

    for t in list_tools:
        base_result[t] = 0
        overall_results[t] = [0,0]

    for sub in comb_2:
            overall_results_comb2[sub] = [0, 0]

    for sub in comb_3:
            overall_results_comb3[sub] = [0, 0]

    for app in list_apps:
        KIUWAN_FILE.write("=============================================================== " + app + " ===============================================================\n")
        results = {}
        tool = ""
        for index, row in xl[app].iterrows():
            r = []
            for column, value in row.items():
                r.append(str(value).replace('\n', ' ').replace('\r', ''))
            
            if r[0] != "nan":
                if r[0] in list_tools:
                    tool = r[0]
                    #print(r)
                else:
                    if tool == "Kiuwan":
                        r[1] = int(float(r[1]))
                        KIUWAN_FILE.write("FP:" + str(r[0:3]) + "\n")
                    tupl = (r[0].split("/")[-1], int(float(r[1])), r[2])
                    if tupl not in results:
                        results[tupl] = copy.copy(base_result)
                        results[tupl][tool] = 1
                #print(r)
                
        print("\n======================= " + app + " =======================")
        print("##############################################################")
        print("###########################SINGULAR###########################")
        res = {}
        per_vuln = {}
        for t in list_tools:
            res[t] = [0, 0] #TN, FP
            per_vuln[t] = copy.deepcopy(dic)

        for k, v in results.items():
            for t in list_tools:
                res[t][v[t]] += 1
                per_vuln[t][k[2]][v[t]] += 1

        KIUWAN_FILE.write("\n")

        for t in list_tools:
            overall_results[t][0] += res[t][0]
            overall_results[t][1] += res[t][1]
            for vuln, value in per_vuln[t].items():
                vulning[vuln][t][4] += value[1]
                vulning[vuln][t][5] += value[0]

                latex[app][t][vuln][4] += value[1]
                latex[app][t][vuln][5] += value[0]

                print("Vulnerability \"" + vuln + "\":", "TN: " + str(value[0]) + "|", "FP: " + str(value[1]) + "|")
                if t == "Kiuwan":
                    KIUWAN_FILE.write("Vulnerability \"" + vuln + "\": " + "TN: " + str(value[0]) + "|"  + "FP: " + str(value[1]) + "|\n",)
            print("[" + t + "]:", "TN: " + str(res[t][0]) + " |", "FP: " + str(res[t][1]) + " |\n")
            if t == "Kiuwan":
                KIUWAN_FILE.write("[" + t + "]: " + "TN: " + str(res[t][0]) + "| " + "FP: " + str(res[t][1]) + " |\n\n")


        
        #COMBINATION 2 RESULTS
        print("##############################################################")
        print("########################COMBINATIONS 2########################")
        res = {}
        per_vuln = {}
        for sub in comb_2:
            res[sub] = [0, 0]
            per_vuln[sub] = copy.deepcopy(dic)

        for k, v in results.items():
             for sub in comb_2:
                res[sub][v[sub[0]] | v[sub[1]]] += 1
                per_vuln[sub][k[2]][v[sub[0]] | v[sub[1]]] += 1

        for sub in comb_2:
            overall_results_comb2[sub][0] += res[sub][0]
            overall_results_comb2[sub][1] += res[sub][1]
            for vuln, value in per_vuln[sub].items():
                print("Vulnerability \"" + vuln + "\":", "TN: " + str(value[0]) + "|", "FP: " + str(value[1]) + "|")
            print("[" + str(sub) + "]:", "TN: " + str(res[sub][0]) + " |", "FP: " + str(res[sub][1]) + " |\n")

        #COMBINATION 3 RESULTS
        print("##############################################################")
        print("########################COMBINATIONS 3########################")
        res = {}
        per_vuln = {}
        for sub in comb_3:
            res[sub] = [0, 0]
            per_vuln[sub] = copy.deepcopy(dic)

        for k, v in results.items():
             for sub in comb_3:
                res[sub][v[sub[0]] | v[sub[1]] | v[sub[2]]] += 1
                per_vuln[sub][k[2]][v[sub[0]] | v[sub[1]] | v[sub[2]]] += 1


        for sub in comb_3:
            overall_results_comb3[sub][0] += res[sub][0]
            overall_results_comb3[sub][1] += res[sub][1]
            for vuln, value in per_vuln[sub].items():
                print("Vulnerability \"" + vuln + "\":", "TN: " + str(value[0]) + "|", "FP: " + str(value[1]) + "|")

            print("[" + str(sub) + "]:", "TN: " + str(res[sub][0]) + " |", "FP: " + str(res[sub][1]) + " |\n")
    
    print("\n\n\n\n\n\n\n\n##############################################################")
    print("###########################OVERALL 1############################")
    for t in list_tools:
        print("[" + str(t) + "]:", "TN: " + str(overall_results[t][0]) + " |", "FP: " + str(overall_results[t][1]) + " |")

    print("###########################OVERALL 2############################")
    for sub in comb_2:
        print("[" + str(sub) + "]:", "TN: " + str(overall_results_comb2[sub][0]) + " |", "FP: " + str(overall_results_comb2[sub][1]) + " |")

    print("###########################OVERALL 3############################")
    for sub in comb_3:
        print("[" + str(sub) + "]:", "TN: " + str(overall_results_comb3[sub][0]) + " |", "FP: " + str(overall_results_comb3[sub][1]) + " |")

    return overall_results, overall_results_comb2, overall_results_comb3, vulning, latex

def weights(vulning, metrics):
    ranks = {}
    wghts = {}
    wi = 0.895/7
    x = 0.005
    len_tools = len(vulning["XSS"].items())
    file_weights = open("weights_table/WEIGHTS.txt", "w")

    for k, v in vulning.items():
        #print(k)
        ranks[k] = [[],[],[],[]]
        wghts[k] = [[],[],[],[]]
        for k2, v2 in v.items():
            metrics[k][k2][0] = recall(vulning[k][k2][0], vulning[k][k2][1])
            metrics[k][k2][1] = recall(vulning[k][k2][0], vulning[k][k2][1])*informedness(vulning[k][k2][0], vulning[k][k2][1], vulning[k][k2][2] + vulning[k][k2][4], vulning[k][k2][3] + vulning[k][k2][5])
            metrics[k][k2][4] = precision(vulning[k][k2][0], vulning[k][k2][2] + vulning[k][k2][4])
            metrics[k][k2][2] = f_measure(metrics[k][k2][4], metrics[k][k2][0])
            metrics[k][k2][3] = markedness(vulning[k][k2][0], vulning[k][k2][1], vulning[k][k2][2] + vulning[k][k2][4], vulning[k][k2][3] + vulning[k][k2][5])
            #print((vulning[k][k2][0], vulning[k][k2][2] + vulning[k][k2][4]))
            #print(k2, "recall:" + str(metrics[k][k2][0]), "recall*informedness:" + str(metrics[k][k2][1]), "f-measure:" + str(metrics[k][k2][2]), "markedness:" + str(metrics[k][k2][3]), "precision:" + str(metrics[k][k2][4]))
            ranks[k][0].append([k2, metrics[k][k2][0], metrics[k][k2][4]])
            ranks[k][1].append([k2, metrics[k][k2][1], metrics[k][k2][0]])
            ranks[k][2].append([k2, metrics[k][k2][2], metrics[k][k2][0]])
            ranks[k][3].append([k2, metrics[k][k2][3], metrics[k][k2][4]])
        
        ranks[k][0] = sorted(ranks[k][0], key=cmp_to_key(compare))
        ranks[k][1] = sorted(ranks[k][1], key=cmp_to_key(compare))
        ranks[k][2] = sorted(ranks[k][2], key=cmp_to_key(compare))
        ranks[k][3] = sorted(ranks[k][3], key=cmp_to_key(compare))

        wghts[k] = [0,0,0,0]
        for i in range(4):
            wghts[k][i] = {}
            temp = [ranks[k][i][0][0]]

            for j in range(len_tools):
                wghts[k][i][ranks[k][i][j][0]] = wi + (len_tools-j-1)*x

                if j != 0:
                    if ranks[k][i][j][1] == ranks[k][i][j-1][1] and ranks[k][i][j][2] == ranks[k][i][j-1][2]:
                        temp.append(ranks[k][i][j][0])
                    else:
                        summ = 0
                        for tmp in temp:
                            summ += wghts[k][i][tmp]
                        
                        for tmp in temp:
                            wghts[k][i][tmp] = summ/len(temp)
                        
                        temp = [ranks[k][i][j][0]]

                if j == len_tools-1:
                    summ = 0
                    for tmp in temp:
                        summ += wghts[k][i][tmp]
                    
                    for tmp in temp:
                        wghts[k][i][tmp] = summ/len(temp)
        
        file_weights.write(k + "\n")
        for k2, v2 in v.items():
            file_weights.write(k2 + " ")
            for i in range(4):
                if i==3:
                    file_weights.write(str(round(wghts[k][i][k2],4)) + "\n")
                else:
                    file_weights.write(str(round(wghts[k][i][k2],4)) + " ")

        file_weights.write("\n\n")

    return wghts

def recall(tp, fn):
    if tp+fn == 0:
        return 0

    return tp/(tp+fn)

def informedness(tp, fn, fp, tn):
    if tp+fn == 0 and fp+tn == 0:
        return 0

    if fp+tn == 0:
        return (tp/(tp+fn)+1)/2

    if tp+fn == 0:
        return (- fp/(fp+tn)+1)/2

    return (tp/(tp+fn) - fp/(fp+tn)+1)/2

def markedness(tp, fn, fp, tn):
    if tp+fp == 0 and fn+tn == 0:
        return 0

    if fn+tn == 0:
        return (tp/(tp+fp)+1)/2

    if tp+fp == 0:
        return (- fn/(fn+tn)+1)/2

    return (tp/(tp+fp) - fn/(fn+tn)+1)/2

def precision(tp, fp):
    if tp+fp == 0:
        return 0

    return tp/(tp+fp)

def f_measure(precision, recall):
    if precision+recall == 0:
        return 0
    return (2*precision*recall)/(precision+recall)

def main():
    dic = {"PATH TRANSVERSAL": [0,0,0,0], "XSS": [0,0,0,0], "INSECURE ALGORITHM": [0,0,0,0], "OUTPUT NEUTRALIZATION OF LOGS": [0,0,0,0],
           "SSRF": [0,0,0,0], "HARDCODED CREDENTIALS": [0,0,0,0], "SQL INJECTION": [0,0,0,0], "WEAK HASH": [0,0,0,0], "HTTP SPLITTING": [0,0,0,0],
           "HARDCODED CONSTANTS": [0,0,0,0], "BYPASS AUTHORIZATION": [0,0,0,0], "CSRF": [0,0,0,0], "INSECURE DESERIALIZATION": [0,0,0,0],
           "XXE": [0,0,0,0], "BAD PROGRAMMING COOKIES": [0,0,0,0], "WEAK RANDOM": [0,0,0,0], "LDAP INJECTION": [0,0,0,0],
           "METHOD TAMPERING": [0,0,0,0], "OUTDATED COMPONENTS": [0,0,0,0], "IMPROPER ERROR HANDLING": [0,0,0,0], "INSECURE ALGORITHM": [0,0,0,0], 
           "OS COMMAND INJECTION": [0,0,0,0], "XPATH": [0,0,0,0], "BYPASS AUTHENTICATION": [0,0,0,0], "TRUST BOUNDARY": [0,0,0,0], }

    list_tools = ["Snyk", "Fortify", "Semgrep", "Synopsis", "Horusec", "Kiuwan", "SpotBugs"]
    comb_2 = list(itertools.combinations(list_tools, 2))
    comb_3 = list(itertools.combinations(list_tools, 3))

    list_vulns = ["BYPASS AUTHORIZATION", "INSUFFICIENT SESSION EXPIRATION", "PATH TRANSVERSAL", "CSRF", "INSECURE ALGORITHM", "WEAK HASH", "SEED HARDCODED",
                  "WEAK RANDOM", "OS COMMAND INJECTION", "SQL INJECTION", "LDAP INJECTION", "XSS", "XPATH", "HTTP SPLITTING", "IMPROPER ERROR HANDLING", 
                  "TRUST BOUNDARY", "METHOD TAMPERING", "XXE", "BAD PROGRAMMING COOKIES", "HARDCODED CONSTANTS", "OUTDATED COMPONENTS", "BYPASS AUTHENTICATION",
                  "HARDCODED CREDENTIALS", "INSECURE DESERIALIZATION", "OUTPUT NEUTRALIZATION OF LOGS", "SSRF"]

    vulning = {}
    metrics = {}
    for v in list_vulns:
        vulning[v] = {}
        metrics[v] = {}
        for t in list_tools:
            vulning[v][t] = [0,0,0,0,0,0] #tp, fn, fp, tn, fpfp, tnfp
            metrics[v][t] = [0,0,0,0,0,0] #recall, recall*informedness, f-measure, markedness, precision
    
    vulning_benchmark = open("initial_vulning/VULNING_BENCHMARK.txt", "r")
    vuln_bench_line = vulning_benchmark.readlines()
    line = 0
    for i in range(len(vuln_bench_line)):
        if line != i:
            pass
        else:
            vuln = vuln_bench_line[i][:-1]
            line += 1
            for j in range(len(list_tools)):
                l_splitted = vuln_bench_line[line+j][:-1].split(" ")
                vulning[vuln][l_splitted[0]][0] += int(l_splitted[2])
                vulning[vuln][l_splitted[0]][1] += int(l_splitted[4])
                vulning[vuln][l_splitted[0]][2] += int(l_splitted[6])
                vulning[vuln][l_splitted[0]][3] += int(l_splitted[8])
            line += len(list_tools)+2


    vulning_juliet = open("initial_vulning/VULNING_JULIET.txt", "r")
    vuln_juliet_line = vulning_juliet.readlines()
    line = 0
    for i in range(len(vuln_juliet_line)):
        if line != i:
            pass
        else:
            vuln = vuln_juliet_line[i][:-1]
            line += 1
            for j in range(len(list_tools)):
                l_splitted = vuln_juliet_line[line+j][:-1].split(" ")
                vulning[vuln][l_splitted[0]][0] += int(l_splitted[1])
                vulning[vuln][l_splitted[0]][1] += int(l_splitted[3])
                vulning[vuln][l_splitted[0]][2] += int(l_splitted[5])
                vulning[vuln][l_splitted[0]][3] += int(l_splitted[7])
            line += len(list_tools)+2
        

    o1, o2, o3, vulning, results, list_apps, latex, latex_categories, latex_vulns = analyse_results(copy.deepcopy(dic), vulning)
    print("\n\n\n\n\n\n\n\n============================================================================================\n\n\n\n\n\n\n\n")
    o1_fp, o2_fp, o3_fp, vulning, latex = analyse_false_positives(copy.deepcopy(dic), vulning, list_apps, latex, latex_categories, latex_vulns)

    

    for t in list_tools:
        print("[" + t + "]:", "TP: " + str(o1[t][0]), "FN: " + str(o1[t][1]), "FP: " + str(o1[t][2]+o1_fp[t][1]), "TN: " + str(o1[t][3]+o1_fp[t][0]))
        #print("[" + t + "]:", "Recall: " + str(recall(o1[t][0], o1[t][1])), "Informedness (JRC): " + str(recall(o1[t][0], o1[t][1])*(informedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0])+1)/2), "Markedness: " + str(markedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0])), "F-Measure: " + str(f_measure(recall(o1[t][0], o1[t][1]), precision(o1[t][0], o1[t][2]+o1_fp[t][1]))), "Precision: " + str(precision(o1[t][0], o1[t][2]+o1_fp[t][1])))
        #print(informedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0]), recall(o1[t][0], o1[t][1])*(informedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0])+1)/2, recall(o1[t][0], o1[t][1])*recall(o1[t][0], o1[t][1])*(informedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0])+1)/2)
        #print((recall(o1[t][0], o1[t][1])+(informedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0]))+1)/3)
    
    print()
    print()
    print()

    for sub in comb_2:
        t = sub
        o1 = o2
        o1_fp = o2_fp 
        print("[" + str(t) + "]:", "TP: " + str(o1[t][0]), "FN: " + str(o1[t][1]), "FP: " + str(o1[t][2]+o1_fp[t][1]), "TN: " + str(o1[t][3]+o1_fp[t][0]))
        #print("[" + str(t) + "]:", "Recall: " + str(recall(o1[t][0], o1[t][1])), "Informedness (JRC): " + str(recall(o1[t][0], o1[t][1])*(informedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0])+1)/2), "Markedness: " + str(markedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0])), "F-Measure: " + str(f_measure(recall(o1[t][0], o1[t][1]), precision(o1[t][0], o1[t][2]+o1_fp[t][1]))), "Precision: " + str(precision(o1[t][0], o1[t][2]+o1_fp[t][1])))

    print()
    print()
    print()

    for sub in comb_3:
        t = sub
        o1 = o3
        o1_fp = o3_fp 
        print("[" + str(t) + "]:", "TP: " + str(o1[t][0]), "FN: " + str(o1[t][1]), "FP: " + str(o1[t][2]+o1_fp[t][1]), "TN: " + str(o1[t][3]+o1_fp[t][0]))
        #print("[" + str(t) + "]:", "Recall: " + str(recall(o1[t][0], o1[t][1])), "Informedness (JRC): " + str(recall(o1[t][0], o1[t][1])*(informedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0])+1)/2), "Markedness: " + str(markedness(o1[t][0], o1[t][1], o1[t][2]+o1_fp[t][1], o1[t][3]+o1_fp[t][0])), "F-Measure: " + str(f_measure(recall(o1[t][0], o1[t][1]), precision(o1[t][0], o1[t][2]+o1_fp[t][1]))), "Precision: " + str(precision(o1[t][0], o1[t][2]+o1_fp[t][1])))

    file_per_vuln = open("initial_vulning/VULNING.txt", "w")

    for v in list_vulns:
        file_per_vuln.write(v + ":\n")
        for t in list_tools: 
            if t == "SpotBugs":
                vulning[v][t][1] = vulning[v]["Snyk"][0]+vulning[v]["Snyk"][1]-vulning[v][t][0]
                vulning[v][t][3] = vulning[v]["Snyk"][2]+vulning[v]["Snyk"][4] + vulning[v]["Snyk"][3]+vulning[v]["Snyk"][5] - vulning[v][t][2]
                vulning[v][t][5] = 0
                
            file_per_vuln.write("\t"+ t + ":" + " TP: " + str(vulning[v][t][0]) 
                                              + " |FN: " + str(vulning[v][t][1]) 
                                              + " |FP: " + str(vulning[v][t][2] + vulning[v][t][4]) 
                                              + " |TN: " + str(vulning[v][t][3] + vulning[v][t][5]) + "|\n")

        file_per_vuln.write("\n\n")   
    #tp, fn, fp, tn, fpfp, tnfp        
    
    LATEX = open("latex_of_other_applications/LATEX.txt", "w")
    t_1st = ["Snyk", "Fortify", "Semgrep", "SpotBugs"]
    t_2nd = ["Synopsis", "Kiuwan", "Horusec"]
    for app in list_apps:
        LATEX.write("\\begin{tiny}\n")
        LATEX.write("\\captionsetup{font=footnotesize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\setlength{\\tabcolsep}{3pt}\n")
        LATEX.write("\\begin{longtable}{*{1}{|m{1.5in}|} *{3}{>{\\columncolor{anti-flashwhite}}wc{0.35cm}|}")

        flg = 0
        for t in t_1st:
            LATEX.write(" *{4}{" + ("" if flg == 0 else ">{\\columncolor{anti-flashwhite}}") + "wc{0.35cm}|}")
            flg ^=1

        LATEX.write("}\n")

        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray}\\multicolumn{4}{|c|}{Vulnerability} & \\multicolumn{" + str(4*len(t_1st)) + "}{c|}{Tools} \\\\\n")
        LATEX.write("\\hline\n")
        
        LATEX.write("\\rowcolor{lightgray} {Name} &  \\multicolumn{3}{c|}{Total}")
        for t in t_1st:
            LATEX.write(" & \\multicolumn{4}{c|}{" + t + "}")

        LATEX.write("\\\\\n\\hline\n")
        
        for c, vulns in latex_categories.items():
            LATEX.write("\\rowcolor{lightlightgray} " + c + " & P & N & NN")
            LATEX.write(" & TP & FN & FP & TN"*len(t_1st))
            
            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")

            for k in vulns:
                LATEX.write(latex_vulns[k] + " & " +  str(latex[app]["Snyk"][k][0]+latex[app]["Snyk"][k][1]) +  " & " + str(latex[app]["Snyk"][k][2]+latex[app]["Snyk"][k][3]) +  " & " + str(latex[app]["Snyk"][k][4]+latex[app]["Snyk"][k][5]))
                for t in t_1st:
                    LATEX.write(" & " + str(latex[app][t][k][0]) + " & " + str(latex[app][t][k][1]) + " & " + str(latex[app][t][k][2]+latex[app][t][k][4]) + " & " + str(latex[app][t][k][3]+latex[app][t][k][5]))

                LATEX.write("\\\\\n")
                LATEX.write("\\hline"+ "\n")
            LATEX.write("\n")

        LATEX.write("\\caption{SAST tools output in relation to the " + app +  " - Part1}\n")
        LATEX.write("\\label{table:SAST tools output in relation to the " + app +  " web application - Part1}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\end{tiny}\n")
        
        LATEX.write("\n\n\n")
        
        LATEX.write("\\begin{tiny}\n")
        LATEX.write("\\captionsetup{font=footnotesize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\setlength{\\tabcolsep}{3pt}\n")
        LATEX.write("\\begin{longtable}{*{1}{|m{1.5in}|} *{3}{>{\\columncolor{anti-flashwhite}}wc{0.35cm}|}")

        flg = 0
        for t in t_2nd:
            LATEX.write(" *{4}{" + ("" if flg == 0 else ">{\\columncolor{anti-flashwhite}}") + "wc{0.35cm}|}")
            flg ^=1

        LATEX.write("}\n")

        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray}\\multicolumn{4}{|c|}{Vulnerability} & \\multicolumn{" + str(4*len(t_2nd)) + "}{c|}{Tools} \\\\\n")
        LATEX.write("\\hline\n")
        
        LATEX.write("\\rowcolor{lightgray} {Name} &  \\multicolumn{3}{c|}{Total}")
        for t in t_2nd:
            LATEX.write(" & \\multicolumn{4}{c|}{" + t + "}")

        LATEX.write("\\\\\n\\hline\n")
        
        for c, vulns in latex_categories.items():
            LATEX.write("\\rowcolor{lightlightgray} " + c + " & P & N & NN")
            LATEX.write(" & TP & FN & FP & TN"*len(t_2nd))
            
            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")

            for k in vulns:
                LATEX.write(latex_vulns[k] + " & " +  str(latex[app]["Snyk"][k][0]+latex[app]["Snyk"][k][1]) +  " & " + str(latex[app]["Snyk"][k][2]+latex[app]["Snyk"][k][3]) +  " & " + str(latex[app]["Snyk"][k][4]+latex[app]["Snyk"][k][5]))
                for t in t_2nd:
                    LATEX.write(" & " + str(latex[app][t][k][0]) + " & " + str(latex[app][t][k][1]) + " & " + str(latex[app][t][k][2]+latex[app][t][k][4]) + " & " + str(latex[app][t][k][3]+latex[app][t][k][5]))

                LATEX.write("\\\\\n")
                LATEX.write("\\hline"+ "\n")
            LATEX.write("\n")

        LATEX.write("\\caption{SAST tools output in relation to the " + app +  " - Part2}\n")
        LATEX.write("\\label{table:SAST tools output in relation to the " + app +  " web application - Part2}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\end{tiny}\n")
        
        LATEX.write("\n\n")
        LATEX.write("\\newpage")

        LATEX.write("\n\n\n")
    
    wghts = weights(vulning, metrics)                  
    analyse_results_weighted(wghts)
    analyse_results_fp_weighted(wghts)

if __name__=="__main__":
    main()